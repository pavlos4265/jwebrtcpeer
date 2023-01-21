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
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import jwebrtcpeer.srtp.crypto.SRTPCipher;

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
public class SRTPCryptoContext extends BaseCryptoContext {
	/**
	 * Secondary cipher for decrypting packets in auth-only mode.
	 */
	protected SRTPCipher cipherAuthOnly;

	/**
	 * For the receiver only, the rollover counter guessed from the sequence number
	 * of the received packet that is currently being processed (i.e. the value is
	 * valid during the execution of
	 * {@link #reverseTransformPacket(ByteArrayBuffer, boolean)} only.) RFC 3711
	 * refers to it by the name {@code v}.
	 */
	private int guessedROC;

	/**
	 * RFC 3711: a 32-bit unsigned rollover counter (ROC), which records how many
	 * times the 16-bit RTP sequence number has been reset to zero after passing
	 * through 65,535. Unlike the sequence number (SEQ), which SRTP extracts from
	 * the RTP packet header, the ROC is maintained by SRTP as described in Section
	 * 3.3.1.
	 */
	private int roc;

	/**
	 * RFC 3711: for the receiver only, a 16-bit sequence number {@code s_l}, which
	 * can be thought of as the highest received RTP sequence number (see Section
	 * 3.3.1 for its handling), which SHOULD be authenticated since message
	 * authentication is RECOMMENDED.
	 */
	private int s_l = 0;

	/**
	 * The indicator which determines whether this instance is used by an SRTP
	 * sender ({@code true}) or receiver ({@code false}).
	 */
	private final boolean sender;

	/**
	 * The indicator which determines whether {@link #s_l} has seen set i.e.
	 * appropriately initialized.
	 */
	private boolean seqNumSet = false;

	/**
	 * Constructs a normal SrtpCryptoContext based on the given parameters.
	 *
	 * @param sender  {@code true} if the new instance is to be used by an SRTP
	 *                sender; {@code false} if the new instance is to be used by an
	 *                SRTP receiver
	 * @param ssrc    the RTP SSRC that this SRTP cryptographic context protects.
	 * @param roc     the initial Roll-Over-Counter according to RFC 3711. These are
	 *                the upper 32 bit of the overall 48 bit SRTP packet index.
	 *                Refer to chapter 3.2.1 of the RFC.
	 * @param masterK byte array holding the master key for this SRTP cryptographic
	 *                context. Refer to chapter 3.2.1 of the RFC about the role of
	 *                the master key.
	 * @param masterS byte array holding the master salt for this SRTP cryptographic
	 *                context. It is used to computer the initialization vector that
	 *                in turn is input to compute the session key, session
	 *                authentication key and the session salt.
	 * @param policy  SRTP policy for this SRTP cryptographic context, defined the
	 *                encryption algorithm, the authentication algorithm, etc
	 *
	 * @throws GeneralSecurityException when the ciphers for the policy are
	 *                                  unavailable
	 */
	public SRTPCryptoContext(boolean sender, int ssrc, int roc, byte[] masterK, byte[] masterS, SRTPPolicy policy)
			throws GeneralSecurityException {
		super(ssrc, masterK, masterS, policy);

		this.sender = sender;
		this.roc = roc;

		cipherAuthOnly = cipher;

		deriveSrtpKeys(masterK, masterS);
	}

	/**
	 * Authenticates a specific packet (as a {@link ByteArrayBuffer}) if the
	 * {@code policy} of this {@link SRTPCryptoContext} specifies that
	 * authentication is to be performed.
	 *
	 * @param pkt the packet (as a {@link ByteArrayBuffer}) to authenticate
	 * @return {@code true} if the {@code policy} of this {@link SRTPCryptoContext}
	 *         specifies that authentication is to not be performed or {@code pkt}
	 *         was successfully authenticated; otherwise, {@code false}
	 */
	private SRTPErrorStatus authenticatePacket(RawPacket pkt) {
		if (policy.getAuthType() != SRTPPolicy.NULL_AUTHENTICATION) {
			int tagLength = policy.getAuthTagLength();

			// get original authentication and store in tempStore
			pkt.readRegionToBuff(pkt.getLength() - tagLength, tagLength, tempStore);

			pkt.shrink(tagLength);

			// save computed authentication in tagStore
			byte[] tagStore = authenticatePacketHmac(pkt, guessedROC);

			// compare authentication tags using constant time comparison
			int nonEqual = 0;
			for (int i = 0; i < tagLength; i++) {
				nonEqual |= (tempStore[i] ^ tagStore[i]);
			}
			if (nonEqual != 0)
				return SRTPErrorStatus.AUTH_FAIL;
		}
		return SRTPErrorStatus.OK;
	}

	/**
	 * Checks if a packet is a replayed based on its sequence number. The method
	 * supports a 64 packet history relative the the specified sequence number. The
	 * sequence number is guaranteed to be real (i.e. not faked) through
	 * authentication.
	 *
	 * @param seqNo        sequence number of the packet
	 * @param guessedIndex guessed ROC
	 * @return {@code true} if the specified sequence number indicates that the
	 *         packet is not a replayed one; {@code false}, otherwise
	 */
	SRTPErrorStatus checkReplay(int seqNo, long guessedIndex) {
		// Compute the index of the previously received packet and its delta to
		// the newly received packet.
		long localIndex = (((long) roc) << 16) | s_l;
		long delta = guessedIndex - localIndex;

		if (delta > 0) {
			return SRTPErrorStatus.OK; // Packet not received yet.
		} else if (-delta >= REPLAY_WINDOW_SIZE) {
			if (sender) {
				/*
				 * logger.error(() -> "Discarding RTP packet with sequence number " + seqNo +
				 * ", SSRC " + (0xFFFFFFFFL & ssrc) +
				 * " because it is outside the replay window! (roc " + roc + ", s_l " + s_l +
				 * ", guessedROC " + guessedROC);
				 */
			}
			return SRTPErrorStatus.REPLAY_OLD; // Packet too old.
		} else if (((replayWindow >>> (-delta)) & 0x1) != 0) {
			if (sender) {
				/*
				 * logger.error(() -> "Discarding RTP packet with sequence number " + seqNo +
				 * ", SSRC " + (0xFFFFFFFFL & ssrc) +
				 * " because it has been received already! (roc " + roc + ", s_l " + s_l +
				 * ", guessedROC " + guessedROC);
				 */
			}
			return SRTPErrorStatus.REPLAY_FAIL; // Packet received already!
		} else {
			return SRTPErrorStatus.OK; // Packet not received yet.
		}
	}

	/**
	 * Derives the srtp session keys from the master key
	 */
	private void deriveSrtpKeys(byte[] masterKey, byte[] masterSalt) throws GeneralSecurityException {
		SRTPKdf kdf = new SRTPKdf(masterKey, masterSalt, policy);

		// compute the session salt
		kdf.deriveSessionKey(saltKey, SRTPKdf.LABEL_RTP_SALT);

		// compute the session encryption key
		if (cipher != null) {
			byte[] encKey = new byte[policy.getEncKeyLength()];
			kdf.deriveSessionKey(encKey, SRTPKdf.LABEL_RTP_ENCRYPTION);
			cipher.init(encKey, saltKey);
			if (cipherAuthOnly != cipher) {
				cipherAuthOnly.init(encKey, saltKey);
			}
		}

		// compute the session authentication key
		if (mac != null) {
			byte[] authKey = new byte[policy.getAuthKeyLength()];
			kdf.deriveSessionKey(authKey, SRTPKdf.LABEL_RTP_MSG_AUTH);
			mac.init(new SecretKeySpec(authKey, mac.getAlgorithm()));
			Arrays.fill(authKey, (byte) 0);
		}
	}

	/**
	 * For the receiver only, determines/guesses the SRTP index of a received SRTP
	 * packet with a specific sequence number.
	 *
	 * @param seqNo the sequence number of the received SRTP packet
	 * @return the SRTP index of the received SRTP packet with the specified
	 *         {@code seqNo}
	 */
	private long guessIndex(int seqNo) {
		if (s_l < 32768) {
			if (seqNo - s_l > 32768)
				guessedROC = roc - 1;
			else
				guessedROC = roc;
		} else {
			if (s_l - 32768 > seqNo)
				guessedROC = roc + 1;
			else
				guessedROC = roc;
		}

		return (((long) guessedROC) << 16) | seqNo;
	}

	/**
	 * Performs Counter Mode AES encryption/decryption
	 *
	 * @param pkt the RTP packet to be encrypted/decrypted
	 */
	private void processPacketAesCm(RawPacket pkt) throws GeneralSecurityException {
		int ssrc = getSsrc(pkt);
		int seqNo = getSequenceNumber(pkt);
		long index = (((long) guessedROC) << 16) | seqNo;

		// byte[] iv = new byte[16];
		ivStore[0] = saltKey[0];
		ivStore[1] = saltKey[1];
		ivStore[2] = saltKey[2];
		ivStore[3] = saltKey[3];

		int i;

		for (i = 4; i < 8; i++) {
			ivStore[i] = (byte) ((0xFF & (ssrc >> ((7 - i) * 8))) ^ saltKey[i]);
		}

		for (i = 8; i < 14; i++) {
			ivStore[i] = (byte) ((0xFF & (byte) (index >> ((13 - i) * 8))) ^ saltKey[i]);
		}

		ivStore[14] = ivStore[15] = 0;

		int rtpHeaderLength = getTotalHeaderLength(pkt);

		cipher.setIV(ivStore, Cipher.ENCRYPT_MODE);

		cipher.process(pkt.getBuffer(), pkt.getOffset() + rtpHeaderLength, pkt.getLength() - rtpHeaderLength);
	}

	private SRTPErrorStatus processPacketAesGcm(RawPacket pkt, boolean encrypting, boolean skipDecryption) {
		int ssrc = getSsrc(pkt);
		int seqNo = getSequenceNumber(pkt);
		long index = (((long) guessedROC) << 16) | seqNo;

		/*
		 * Compute the SRTP GCM IV (refer to section 8.1 in RFC 7714):
		 *
		 * 0 0 0 0 0 0 0 0 0 0 1 1 0 1 2 3 4 5 6 7 8 9 0 1
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ |00|00| SSRC | ROC | SEQ |---+
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | |
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | | Encryption Salt |->(+)
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | |
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | | Initialization Vector |<--+
		 * +--+--+--+--+--+--+--+--+--+--+--+--+
		 */

		ivStore[0] = saltKey[0];
		ivStore[1] = saltKey[1];

		int i;

		for (i = 2; i < 6; i++) {
			ivStore[i] = (byte) ((0xFF & (ssrc >> ((5 - i) * 8))) ^ saltKey[i]);
		}

		for (i = 6; i < 12; i++) {
			ivStore[i] = (byte) ((0xFF & (byte) (index >> ((11 - i) * 8))) ^ saltKey[i]);
		}

		int rtpHeaderLength = getTotalHeaderLength(pkt);

		try {
			SRTPCipher cipher = skipDecryption ? cipherAuthOnly : this.cipher;

			cipher.setIV(ivStore, encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);

			cipher.processAAD(pkt.getBuffer(), pkt.getOffset(), rtpHeaderLength);

			int processLen = cipher.process(pkt.getBuffer(), pkt.getOffset() + rtpHeaderLength,
					pkt.getLength() - rtpHeaderLength);

			pkt.setLength(processLen + rtpHeaderLength);
		} catch (GeneralSecurityException e) {
			if (encrypting) {
				// logger.debug(() -> "Error encrypting SRTP packet: " + e.getMessage());
				return SRTPErrorStatus.FAIL;
			} else {
				return SRTPErrorStatus.AUTH_FAIL;
			}
		}
		return SRTPErrorStatus.OK;
	}

	/**
	 * Performs F8 Mode AES encryption/decryption
	 *
	 * @param pkt the RTP packet to be encrypted/decrypted
	 */
	private void processPacketAesF8(RawPacket pkt) throws GeneralSecurityException {
		// 11 bytes of the RTP header are the 11 bytes of the iv
		// the first byte of the RTP header is not used.
		System.arraycopy(pkt.getBuffer(), pkt.getOffset(), ivStore, 0, 12);
		ivStore[0] = 0;

		// set the ROC in network order into IV
		int roc = guessedROC;

		ivStore[12] = (byte) (roc >> 24);
		ivStore[13] = (byte) (roc >> 16);
		ivStore[14] = (byte) (roc >> 8);
		ivStore[15] = (byte) roc;

		int rtpHeaderLength = getTotalHeaderLength(pkt);

		cipher.setIV(ivStore, Cipher.ENCRYPT_MODE);

		cipher.process(pkt.getBuffer(), pkt.getOffset() + rtpHeaderLength, pkt.getLength() - rtpHeaderLength);
	}

	/**
	 * Transforms an SRTP packet into an RTP packet. The method is called when an
	 * SRTP packet is received. Operations done by the this operation include:
	 * authentication check, packet replay check and decryption. Both encryption and
	 * authentication functionality can be turned off as long as the SrtpPolicy used
	 * in this SrtpCryptoContext is requires no encryption and no authentication.
	 * Then the packet will be sent out untouched. However, this is not encouraged.
	 * If no SRTP feature is enabled, then we shall not use SRTP TransformConnector.
	 * We should use the original method (RTPManager managed transportation)
	 * instead.
	 *
	 * @param pkt            the RTP packet that is just received
	 * @param skipDecryption if {@code true}, the decryption of the packet will not
	 *                       be performed (so as not to waste resources when it is
	 *                       not needed). The packet will still be authenticated and
	 *                       the ROC updated.
	 * @return {@link SRTPErrorStatus#OK} if the packet can be accepted; an error
	 *         status if the packet failed authentication or failed replay check
	 */
	synchronized public SRTPErrorStatus reverseTransformPacket(RawPacket pkt, boolean skipDecryption)
			throws GeneralSecurityException {
		if (sender) {
			throw new IllegalStateException("reverseTransformPacket called on SRTP sender");
		}
		if (!validateSRTPPacketLength(pkt, policy.getAuthTagLength())) {
			/* Too short to be a valid SRTP packet */
			return SRTPErrorStatus.INVALID_PACKET;
		}

		int seqNo = getSequenceNumber(pkt);

		/*
		 * logger.debug(() -> "Reverse transform for SSRC " + this.ssrc + " SeqNo=" +
		 * seqNo + " s_l=" + s_l + " seqNumSet=" + seqNumSet + " guessedROC=" +
		 * guessedROC + " roc=" + roc);
		 */

		// Whether s_l was initialized while processing this packet.
		boolean seqNumWasJustSet = false;
		if (!seqNumSet) {
			seqNumSet = true;
			s_l = seqNo;
			seqNumWasJustSet = true;
		}

		// Guess the SRTP index (48 bit), see RFC 3711, 3.3.1
		// Stores the guessed rollover counter (ROC) in this.guessedROC.
		long guessedIndex = guessIndex(seqNo);
		SRTPErrorStatus ret, err;

		// Replay control
		if (policy.isReceiveReplayDisabled() || ((err = checkReplay(seqNo, guessedIndex)) == SRTPErrorStatus.OK)) {
			// Authenticate the packet.
			if ((err = authenticatePacket(pkt)) == SRTPErrorStatus.OK) {
				if (!skipDecryption || policy.getEncType() == SRTPPolicy.AESGCM_ENCRYPTION) {
					switch (policy.getEncType()) {
					// Decrypt the packet using Counter Mode encryption.
					case SRTPPolicy.AESCM_ENCRYPTION:
					case SRTPPolicy.TWOFISH_ENCRYPTION:
						processPacketAesCm(pkt);
						break;

					case SRTPPolicy.AESGCM_ENCRYPTION:
						err = processPacketAesGcm(pkt, false, skipDecryption);
						break;

					// Decrypt the packet using F8 Mode encryption.
					case SRTPPolicy.AESF8_ENCRYPTION:
					case SRTPPolicy.TWOFISHF8_ENCRYPTION:
						processPacketAesF8(pkt);
						break;
					}
				}

				if (err == SRTPErrorStatus.OK) {
					// Update the rollover counter and highest sequence number if
					// necessary.
					update(seqNo, guessedIndex);
				} else {
					// logger.debug(() -> "SRTP auth failed for SSRC " + ssrc);
				}

				ret = err;
			} else {
				// logger.debug(() -> "SRTP auth failed for SSRC " + ssrc);
				ret = err;
			}
		} else {
			ret = err;
		}

		if (ret != SRTPErrorStatus.OK && seqNumWasJustSet) {
			// We set the initial value of s_l as a result of processing this
			// packet, but the packet failed to authenticate. We shouldn't
			// update our state based on an untrusted packet, so we revert
			// seqNumSet.
			seqNumSet = false;
			s_l = 0;
		}

		return ret;
	}

	/**
	 * Transforms an RTP packet into an SRTP packet. The method is called when a
	 * normal RTP packet ready to be sent. Operations done by the transformation may
	 * include: encryption, using either Counter Mode encryption, Galois/Counter
	 * Mode encryption, or F8 Mode encryption, adding authentication tag, currently
	 * HMC SHA1 method. Both encryption and authentication functionality can be
	 * turned off as long as the SrtpPolicy used in this SrtpCryptoContext is
	 * requires no encryption and no authentication. Then the packet will be sent
	 * out untouched. However, this is not encouraged. If no SRTP feature is
	 * enabled, then we shall not use SRTP TransformConnector. We should use the
	 * original method (RTPManager managed transportation) instead.
	 *
	 * @param pkt the RTP packet that is going to be sent out
	 */
	synchronized public SRTPErrorStatus transformPacket(RawPacket pkt) throws GeneralSecurityException {
		if (!sender) {
			throw new IllegalStateException("transformPacket called on SRTP receiver");
		}
		int seqNo = getSequenceNumber(pkt);

		if (!seqNumSet) {
			seqNumSet = true;
			s_l = seqNo;
		}

		// Guess the SRTP index (48 bit), see RFC 3711, 3.3.1
		// Stores the guessed ROC in this.guessedROC
		long guessedIndex = guessIndex(seqNo);

		SRTPErrorStatus err;

		/*
		 * XXX The invocation of the checkReplay method here is not meant as replay
		 * protection but as a consistency check of our implementation.
		 */
		if (policy.isSendReplayEnabled() && (err = checkReplay(seqNo, guessedIndex)) != SRTPErrorStatus.OK)
			return err;

		switch (policy.getEncType()) {
		// Encrypt the packet using Counter Mode encryption.
		case SRTPPolicy.AESCM_ENCRYPTION:
		case SRTPPolicy.TWOFISH_ENCRYPTION:
			processPacketAesCm(pkt);
			break;

		case SRTPPolicy.AESGCM_ENCRYPTION:
			processPacketAesGcm(pkt, true, false);
			break;

		// Encrypt the packet using F8 Mode encryption.
		case SRTPPolicy.AESF8_ENCRYPTION:
		case SRTPPolicy.TWOFISHF8_ENCRYPTION:
			processPacketAesF8(pkt);
			break;
		}

		/* Authenticate the packet. */
		if (policy.getAuthType() != SRTPPolicy.NULL_AUTHENTICATION) {
			byte[] tagStore = authenticatePacketHmac(pkt, guessedROC);
			pkt.append(tagStore, policy.getAuthTagLength());
		}

		// Update the ROC if necessary.
		update(seqNo, guessedIndex);

		return SRTPErrorStatus.OK;
	}

	/**
	 * Logs the current state of the replay window, for debugging purposes.
	 */
	private void logReplayWindow(long newIdx) {
		// logger.debug(() -> "Updated replay window with " + newIdx + ". " +
		// SrtpPacketUtils.formatReplayWindow((roc << 16 | s_l), replayWindow,
		// REPLAY_WINDOW_SIZE));
	}

	/**
	 * For the receiver only, updates the rollover counter (i.e. {@link #roc}) and
	 * highest sequence number (i.e. {@link #s_l}) in this cryptographic context
	 * using the SRTP/packet index calculated by {@link #guessIndex(int)} and
	 * updates the replay list (i.e. {@link #replayWindow}). This method is called
	 * after all checks were successful.
	 *
	 * @param seqNo        the sequence number of the accepted SRTP packet
	 * @param guessedIndex the SRTP index of the accepted SRTP packet calculated by
	 *                     {@code guessIndex(int)}
	 */
	private void update(int seqNo, long guessedIndex) {
		long delta = guessedIndex - ((((long) roc) << 16) | s_l);

		/* Update the replay bit mask. */
		if (delta >= REPLAY_WINDOW_SIZE) {
			replayWindow = 1;
		} else if (delta > 0) {
			replayWindow <<= delta;
			replayWindow |= 1;
		} else {
			replayWindow |= (1L << -delta);
		}

		if (guessedROC == roc) {
			if (seqNo > s_l)
				s_l = seqNo & 0xffff;
		} else if (guessedROC == (roc + 1)) {
			s_l = seqNo & 0xffff;
			roc = guessedROC;
		}

		logReplayWindow(guessedIndex);
	}
}
