/*
 * Copyright @ 2015 - present 8x8, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Some of the code in this class is derived from ccRtp's SRTP implementation,
 * which has the following copyright notice:
 *
 * Copyright (C) 2004-2006 the Minisip Team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
package jwebrtcpeer.srtp;

import java.security.GeneralSecurityException;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.Mac;

import jwebrtcpeer.srtp.crypto.Aes;
import jwebrtcpeer.srtp.crypto.HmacSha1;
import jwebrtcpeer.srtp.crypto.SRTPCipher;
import jwebrtcpeer.srtp.crypto.SRTPCipherCtr;
import jwebrtcpeer.srtp.crypto.SRTPCipherF8;
import jwebrtcpeer.srtp.crypto.SRTPCipherGcm;

/**
 * SrtpCryptoContext class is the core class of SRTP implementation. There can
 * be multiple SRTP sources in one SRTP session. And each SRTP stream has a
 * corresponding SrtpCryptoContext object, identified by SSRC. In this way,
 * different sources can be protected independently.
 *
 * SrtpCryptoContext class acts as a manager class and maintains all the
 * information used in SRTP transformation. It is responsible for deriving
 * encryption/salting/authentication keys from master keys. And it will invoke
 * certain class to encrypt/decrypt (transform/reverse transform) RTP packets.
 * It will hold a replay check db and do replay check against incoming packets.
 *
 * Refer to section 3.2 in RFC3711 for detailed description of cryptographic
 * context.
 *
 * Cryptographic related parameters, i.e. encryption mode / authentication mode,
 * master encryption key and master salt key are determined outside the scope of
 * SRTP implementation. They can be assigned manually, or can be assigned
 * automatically using some key management protocol, such as MIKEY (RFC3830),
 * SDES (RFC4568) or Phil Zimmermann's ZRTP protocol (RFC6189).
 *
 * @author Bing SU (nova.su@gmail.com)
 * @author Lyubomir Marinov
 */
public class BaseCryptoContext {
	/**
	 * The replay check windows size.
	 */
	protected static final long REPLAY_WINDOW_SIZE = 64;

	/**
	 * Cipher to encrypt packets.
	 */
	protected final SRTPCipher cipher;

	/**
	 * Temp store.
	 */
	protected final byte[] ivStore;

	/**
	 * The HMAC object we used to do packet authentication
	 */
	protected final Mac mac; // used for various HMAC computations

	/**
	 * Encryption / Authentication policy for this session
	 */
	protected final SRTPPolicy policy;

	/**
	 * Temp store.
	 */
	protected final byte[] rbStore = new byte[4];

	/**
	 * Bit mask for replay check
	 */
	protected long replayWindow;

	/**
	 * Derived session salting key
	 */
	protected final byte[] saltKey;

	/**
	 * RTP/RTCP SSRC of this cryptographic context
	 */
	protected final int ssrc;

	/**
	 * this is a working store, used by some methods to avoid new operations the
	 * methods must use this only to store results for immediate processing
	 */
	protected final byte[] tempStore = new byte[100];

	/**
	 * The size of the fixed part of the RTP header as defined by RFC 3550.
	 */
	private static final int FIXED_HEADER_SIZE = 12;

	/**
	 * The size of the fixed part of the extension header as defined by RFC 3550.
	 */
	private static final int EXT_HEADER_SIZE = 4;

	protected BaseCryptoContext(int ssrc, byte[] masterK, byte[] masterS, SRTPPolicy policy)
			throws GeneralSecurityException {
		this.ssrc = ssrc;
		this.policy = policy;

		int encKeyLength = policy.getEncKeyLength();

		if (masterK != null) {
			if (masterK.length != encKeyLength) {
				throw new IllegalArgumentException("masterK.length != encKeyLength");
			}
		} else {
			if (encKeyLength != 0) {
				throw new IllegalArgumentException("null masterK but encKeyLength != 0");
			}
		}
		int saltKeyLength = policy.getSaltKeyLength();

		if (masterS != null) {
			if (masterS.length != saltKeyLength) {
				throw new IllegalArgumentException("masterS.length != saltKeyLength");
			}
		} else {
			if (saltKeyLength != 0) {
				throw new IllegalArgumentException("null masterS but saltKeyLength != 0");
			}
		}

		saltKey = new byte[saltKeyLength];
		int ivSize = 16;
		switch (policy.getEncType()) {
		case SRTPPolicy.AESCM_ENCRYPTION:
			cipher = new SRTPCipherCtr(Aes.createCipher("AES/CTR/NoPadding"));
			break;
		case SRTPPolicy.AESGCM_ENCRYPTION:
			if (policy.getAuthTagLength() != 16) {
				throw new IllegalArgumentException("SRTP only supports 16-octet GCM auth tags");
			}
			cipher = new SRTPCipherGcm(Aes.createCipher("AES/GCM/NoPadding"));
			ivSize = 12;
			break;
		case SRTPPolicy.AESF8_ENCRYPTION:
			cipher = new SRTPCipherF8(Aes.createCipher("AES/ECB/NoPadding"));
			break;
		case SRTPPolicy.TWOFISHF8_ENCRYPTION:
			cipher = new SRTPCipherF8(Cipher.getInstance("Twofish/ECB/NoPadding"));
			break;
		case SRTPPolicy.TWOFISH_ENCRYPTION:
			cipher = new SRTPCipherCtr(Cipher.getInstance("Twofish/CTR/NoPadding"));
			break;
		case SRTPPolicy.NULL_ENCRYPTION:
		default:
			cipher = null;
			ivSize = 0;
			break;
		}

		ivStore = new byte[ivSize];

		Mac mac;
		switch (policy.getAuthType()) {
		case SRTPPolicy.HMACSHA1_AUTHENTICATION:
			mac = HmacSha1.createMac();
			break;

		case SRTPPolicy.SKEIN_AUTHENTICATION:
			mac = Mac.getInstance("SkeinMac_512_" + (policy.getAuthTagLength() * 8));
			break;

		case SRTPPolicy.NULL_AUTHENTICATION:
		default:
			mac = null;
			break;
		}
		this.mac = mac;
	}

	/**
	 * Writes roc / index to the rbStore buffer.
	 */
	protected void writeRoc(int rocIn) {
		rbStore[0] = (byte) (rocIn >> 24);
		rbStore[1] = (byte) (rocIn >> 16);
		rbStore[2] = (byte) (rocIn >> 8);
		rbStore[3] = (byte) rocIn;
	}

	/**
	 * Authenticates a packet.
	 *
	 * @param pkt   the RTP packet to be authenticated
	 * @param rocIn Roll-Over-Counter
	 */
	synchronized protected byte[] authenticatePacketHmac(RawPacket pkt, int rocIn) {
		mac.update(pkt.getBuffer(), pkt.getOffset(), pkt.getLength());
		writeRoc(rocIn);
		mac.update(rbStore, 0, rbStore.length);
		return mac.doFinal();
	}

	/**
	 * Gets the authentication tag length of this SRTP cryptographic context
	 *
	 * @return the authentication tag length of this SRTP cryptographic context
	 */
	public int getAuthTagLength() {
		return policy.getAuthTagLength();
	}

	/**
	 * Gets the SSRC of this SRTP cryptographic context
	 *
	 * @return the SSRC of this SRTP cryptographic context
	 */
	public int getSsrc() {
		return ssrc;
	}

	/**
	 * Get the sender SSRC of an SRTCP packet.
	 *
	 * This is the SSRC of the first packet of the compound packet.
	 *
	 * @param buf The buffer holding the SRTCP packet.
	 */
	public static int getSenderSsrc(RawPacket packet) {
		return packet.readInt(4);
	}

	/**
	 * Get the SRTCP index (sequence number) from an SRTCP packet
	 *
	 * @param buf        The buffer holding the SRTCP packet.
	 * @param authTagLen authentication tag length
	 * @return SRTCP sequence num from source packet
	 */
	public static int getIndex(RawPacket packet, int authTagLen) {
		int authTagOffset = packet.getLength() - (4 + authTagLen);
		return packet.readInt(authTagOffset);
	}

	/**
	 * Validate that the contents of a ByteArrayBuffer could contain a valid SRTCP
	 * packet.
	 *
	 * This validates that the packet is long enough to be a valid packet, i.e.
	 * attempts to read fields of the packet will not fail.
	 *
	 * @param buf        The buffer holding the SRTCP packet.
	 * @param authTagLen The length of the packet's authentication tag.
	 * @return true if the packet is syntactically valid (i.e., long enough); false
	 *         if not.
	 */
	public static boolean validateSRTCPPacketLength(RawPacket buf, int authTagLen) {
		int length = buf.getLength();
		int neededLength = 8 /* sender SSRC */ + 4 /* index */ + authTagLen;

		if (length < neededLength) {
			return false;
		}
		return true;
	}

	/**
	 * Returns {@code true} if the extension bit of an SRTP packet has been set and
	 * {@code false} otherwise.
	 *
	 * @param buf The SRTP packet.
	 * @return {@code true} if the extension bit of this packet has been set and
	 *         {@code false} otherwise.
	 */
	static boolean getExtensionBit(RawPacket buf) {
		byte[] buffer = buf.getBuffer();
		int offset = buf.getOffset();

		return (buffer[offset] & 0x10) == 0x10;
	}

	/**
	 * Returns the number of CSRC identifiers included in an SRTP packet.
	 *
	 * Note: this does not verify that the packet is indeed long enough for the
	 * claimed number of CSRCs.
	 *
	 * @param buf The SRTP packet.
	 *
	 * @return the CSRC count for this packet.
	 */
	static int getCsrcCount(RawPacket buf) {
		byte[] buffer = buf.getBuffer();
		int offset = buf.getOffset();

		return buffer[offset] & 0x0f;
	}

	/**
	 * Returns the length of the variable-length part of the header extensions
	 * present in an SRTP packet.
	 *
	 * Note: this does not verify that the header extension bit is indeed set, nor
	 * that the packet is long enough for the header extension specified.
	 *
	 * @param buf The SRTP packet.
	 * @return the length of the extensions present in this packet.
	 */
	public static int getExtensionLength(RawPacket packet) {
		int cc = getCsrcCount(packet);

		// The extension length comes after the RTP header, the CSRC list, and
		// two bytes in the extension header called "defined by profile".
		int extLenIndex = FIXED_HEADER_SIZE + cc * 4 + 2;

		int len = readUint16(packet, extLenIndex) * 4;

		return len;
	}

	/**
	 * Reads the sequence number of an SRTP packet.
	 *
	 * @param buf The buffer holding the SRTP packet.
	 */
	public static int getSequenceNumber(RawPacket packet) {
		return readUint16(packet, 2);
	}

	/**
	 * Reads the SSRC of an SRTP packet.
	 *
	 * @param buf The buffer holding the SRTP packet.
	 */
	public static int getSsrc(RawPacket packet) {
		return packet.readInt(8);
	}

	/**
	 * Validate that the contents of a ByteArrayBuffer could contain a valid SRTP
	 * packet.
	 *
	 * This validates that the packet is long enough to be a valid packet, i.e.
	 * attempts to read fields of the packet will not fail.
	 *
	 * @param buf        The buffer holding the SRTP packet.
	 * @param authTagLen The length of the packet's authentication tag.
	 * @return true if the packet is syntactically valid (i.e., long enough); false
	 *         if not.
	 */
	public static boolean validateSRTPPacketLength(RawPacket buf, int authTagLen) {
		int length = buf.getLength();
		int neededLength = FIXED_HEADER_SIZE + authTagLen;
		if (length < neededLength) {
			return false;
		}

		int cc = getCsrcCount(buf);
		neededLength += cc * 4;
		if (length < neededLength) {
			return false;
		}

		if (getExtensionBit(buf)) {
			neededLength += EXT_HEADER_SIZE;
			if (length < neededLength) {
				return false;
			}

			int extLen = getExtensionLength(buf);
			neededLength += extLen;
			if (length < neededLength) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Gets the total header length of an SRTP packet.
	 *
	 * @param buf The buffer holding the SRTP packet.
	 */
	public static int getTotalHeaderLength(RawPacket buf) {
		int length = FIXED_HEADER_SIZE + getCsrcCount(buf) * 4;

		if (getExtensionBit(buf)) {
			length += EXT_HEADER_SIZE + getExtensionLength(buf);
		}

		return length;
	}

	/**
	 * Formats the current state of an SRTP/SRTCP replay window, for debugging
	 * purposes.
	 */
	public static String formatReplayWindow(long maxIdx, long replayWindow, long replayWindowSize) {
		StringBuilder out = new StringBuilder();
		Formatter formatter = new Formatter(out);
		formatter.format("maxIdx=%d, window=0x%016x: [", maxIdx, replayWindow);

		boolean printedSomething = false;
		for (long i = replayWindowSize - 1; i >= 0; i--) {
			if (((replayWindow >> i) & 0x1) != 0) {
				if (printedSomething) {
					out.append(", ");
				}
				printedSomething = true;
				out.append(maxIdx - i);
			}
		}

		out.append("]");

		formatter.close();

		return out.toString();
	}

	/**
	 * Read a unsigned 16-bit value from a byte array buffer at a specified offset
	 * as an int.
	 *
	 * @param bab the buffer from which to read.
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public static int readUint16(RawPacket packet, int off) {
		return readUint16(packet.getBuffer(), off + packet.getOffset());
	}

	/**
	 * Read a unsigned 16-bit value from a byte array at a specified offset as an
	 * int.
	 *
	 * @param buf the buffer from which to read.
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public static int readUint16(byte[] buf, int off) {
		int b1 = (0xFF & (buf[off++]));
		int b2 = (0xFF & (buf[off]));
		return b1 << 8 | b2;
	}
}
