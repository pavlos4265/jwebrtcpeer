/*
 * Copyright @ 2015 Atlassian Pty Ltd
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
 */
package jwebrtcpeer.srtp;

import java.util.Comparator;
import java.util.Iterator;

/**
 * When using TransformConnector, a RTP/RTCP packet is represented using
 * RawPacket. RawPacket stores the buffer holding the RTP/RTCP packet, as well
 * as the inner offset and length of RTP/RTCP packet data.
 *
 * After transformation, data is also store in RawPacket objects, either the
 * original RawPacket (in place transformation), or a newly created RawPacket.
 *
 * Besides packet info storage, RawPacket also provides some other operations
 * such as readInt() to ease the development process.
 *
 *
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 * @author Bing SU (nova.su@gmail.com)
 * @author Emil Ivov
 * @author Damian Minkov
 * @author Boris Grozev
 * @author Lyubomir Marinov
 * @author George Politis
 */
public class RawPacket extends ByteBuffer {
	/**
	 * The size of the extension header as defined by RFC 3550.
	 */
	public static final int EXT_HEADER_SIZE = 4;

	/**
	 * The size of the fixed part of the RTP header as defined by RFC 3550.
	 */
	public static final int FIXED_HEADER_SIZE = 12;

	/**
	 * The minimum size in bytes of a valid RTCP packet. An empty Receiver Report is
	 * 8 bytes long.
	 */
	private static final int RTCP_MIN_SIZE = 8;

	/**
	 * The bitmask for the RTP sequence number field.
	 */
	public static final int SEQUENCE_NUMBER_MASK = 0xffff;

	/**
	 * The bitmask for the RTP timestamp field.
	 */
	public static final long TIMESTAMP_MASK = 0xFFFF_FFFFL;

	/**
	 * The bitmap/flag mask that specifies the set of boolean attributes enabled for
	 * this <tt>RawPacket</tt>. The value is the logical sum of all of the set
	 * flags. The possible flags are defined by the <tt>FLAG_XXX</tt> constants of
	 * FMJ's {@link javax.media.Buffer} class.
	 */
	private int flags;

	/**
	 * A {@link HeaderExtensions} instance, used to iterate over the RTP header
	 * extensions of this {@link RawPacket}.
	 */
	private HeaderExtensions headerExtensions;

	/**
	 * A flag to skip packet statistics for this packet.
	 */
	private boolean skipStats = false;

	/**
	 * Initializes a new empty <tt>RawPacket</tt> instance.
	 */
	public RawPacket() {
		headerExtensions = null;
	}

	/**
	 * Initializes a new <tt>RawPacket</tt> instance with a specific <tt>byte</tt>
	 * array buffer.
	 *
	 * @param buffer the <tt>byte</tt> array to be the buffer of the new instance
	 * @param offset the offset in <tt>buffer</tt> at which the actual data to be
	 *               represented by the new instance starts
	 * @param length the number of <tt>byte</tt>s in <tt>buffer</tt> which
	 *               constitute the actual data to be represented by the new
	 *               instance
	 */
	public RawPacket(byte[] buffer, int offset, int length) {
		super(buffer, offset, length);
		headerExtensions = new HeaderExtensions();
	}

	/**
	 * Gets the value of the "version" field of an RTP packet.
	 * 
	 * @return the value of the RTP "version" field.
	 */
	public static int getVersion(RawPacket packet) {
		if (packet == null) {
			return -1;
		}

		return getVersion(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Gets the value of the "version" field of an RTP packet.
	 * 
	 * @return the value of the RTP "version" field.
	 */
	public static int getVersion(byte[] buffer, int offset, int length) {
		return (buffer[offset] & 0xC0) >>> 6;
	}

	/**
	 * Test whether the RTP Marker bit is set
	 *
	 * @return true if the RTP Marker bit is set, false otherwise.
	 */
	public static boolean isPacketMarked(RawPacket packet) {
		if (packet == null) {
			return false;
		}

		return isPacketMarked(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Test whether the RTP Marker bit is set
	 *
	 * @return true if the RTP Marker bit is set, false otherwise.
	 */
	public static boolean isPacketMarked(byte[] buffer, int offset, int length) {
		if (buffer == null || buffer.length < offset + length || length < 2) {
			return false;
		}

		return (buffer[offset + 1] & 0x80) != 0;
	}

	/**
	 * Perform checks on the packet represented by this instance and return
	 * <tt>true</tt> if it is found to be invalid. A return value of <tt>false</tt>
	 * does not necessarily mean that the packet is valid.
	 *
	 * @return <tt>true</tt> if the RTP/RTCP packet represented by this instance is
	 *         found to be invalid, <tt>false</tt> otherwise.
	 */
	public static boolean isInvalid(byte[] buffer, int offset, int length) {
		// RTP packets are at least 12 bytes long, RTCP packets can be 8.
		if (buffer == null || buffer.length < offset + length || length < RTCP_MIN_SIZE) {
			return true;
		}

		int pt = buffer[offset + 1] & 0xff;
		if (pt < 200 || pt > 211) {
			// This is an RTP packet.
			return length < FIXED_HEADER_SIZE;
		}

		return false;
	}

	/**
	 * Get RTCP SSRC from a RTCP packet
	 *
	 * @return RTP SSRC from source RTP packet in a {@code long}.
	 */
	public static long getRTCPSSRC(RawPacket packet) {
		if (packet == null || packet.isInvalid()) {
			return -1;
		}

		return getRTCPSSRC(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Get RTCP SSRC from a RTCP packet
	 *
	 * @return RTP SSRC from source RTP packet
	 */
	public static long getRTCPSSRC(byte[] buf, int off, int len) {
		if (buf == null || buf.length < off + len || len < 8) {
			return -1;
		}

		return readUint32AsLong(buf, off + 4);
	}

	/**
	 * Checks whether the RTP/RTCP header is valid or not (note that a valid header
	 * does not necessarily imply a valid packet). It does so by checking the
	 * RTP/RTCP header version and makes sure the buffer is at least 8 bytes long
	 * for RTCP and 12 bytes long for RTP.
	 *
	 * @param buf the byte buffer that contains the RTCP header.
	 * @param off the offset in the byte buffer where the RTCP header starts.
	 * @param len the number of bytes in buffer which constitute the actual data.
	 * @return true if the RTP/RTCP packet is valid, false otherwise.
	 */
	public static boolean isRtpRtcp(byte[] buf, int off, int len) {
		if (isInvalid(buf, off, len)) {
			return false;
		}

		// int version = getVersion(buf, off, len);
		// if (version != RTPHeader.VERSION)
		// {
		// return false;
		// }

		return true;
	}

	/**
	 * Adds the given buffer as a header extension of this packet according the
	 * rules specified in RFC 5285. Note that this method does not replace
	 * extensions so if you add the same buffer twice it would be added as a
	 * separate extension.
	 *
	 * This method MUST NOT be called while iterating over the extensions using
	 * {@link #getHeaderExtensions()}, or while manipulating the state of this
	 * {@link RawPacket}.
	 *
	 * @param id   the ID with which to add the extension.
	 * @param data the buffer containing the extension data.
	 */
	public void addExtension(byte id, byte[] data) {
		addExtension(id, data, data.length);
	}

	/**
	 * Adds the given buffer as a header extension of this packet according the
	 * rules specified in RFC 5285. Note that this method does not replace
	 * extensions so if you add the same buffer twice it would be added as a
	 * separate extension.
	 *
	 * This method MUST NOT be called while iterating over the extensions using
	 * {@link #getHeaderExtensions()}, or while manipulating the state of this
	 * {@link RawPacket}.
	 *
	 * @param id   the ID with which to add the extension.
	 * @param data the buffer containing the extension data.
	 * @param len  the length of the extension.
	 */
	public void addExtension(byte id, byte[] data, int len) {
		if (data == null || len < 1 || len > 16 || data.length < len) {
			throw new IllegalArgumentException(
					"id=" + id + " data.length=" + (data == null ? "null" : data.length) + " len=" + len);
		}

		HeaderExtension he = addExtension(id, len);
		System.arraycopy(data, 0, he.getBuffer(), he.getOffset() + 1, len);
	}

	/**
	 * Adds an RTP header extension with a given ID and a given length to this
	 * packet. The contents of the extension are not set to anything, and the caller
	 * of this method is responsible for filling them in.
	 *
	 * This method MUST NOT be called while iterating over the extensions using
	 * {@link #getHeaderExtensions()}, or while manipulating the state of this
	 * {@link RawPacket}.
	 *
	 * @param id  the ID of the extension to add.
	 * @param len the length in bytes of the extension to add.
	 * @return the header extension which was added.
	 */
	public HeaderExtension addExtension(byte id, int len) {
		if (id < 1 || id > 15 || len < 1 || len > 16) {
			throw new IllegalArgumentException("id=" + id + " len=" + len);
		}

		// The byte[] of a RawPacket has the following structure:
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// | A: unused | B: hdr + ext | C: payload | D: unused |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// And the regions have the following sizes:
		// A: this.offset
		// B: this.getHeaderLength()
		// C: this.getPayloadLength()
		// D: this.buffer.length - this.length - this.offset
		// We will try to extend the packet so that it uses A and/or D if
		// possible, in order to avoid allocating new memory.

		// We get this early, before we modify the buffer.
		int payloadLength = getPayloadLength();
		boolean extensionBit = getExtensionBit();
		int extHeaderOffset = FIXED_HEADER_SIZE + 4 * getCsrcCount();

		// This is an upper bound on the required length for the packet after
		// the addition of the new extension. It is easier to calculate than
		// the exact number, and is relatively close (it may be off by a few
		// bytes due to padding)
		int maxRequiredLength = getLength() + (extensionBit ? 0 : EXT_HEADER_SIZE) + 1 /*
																						 * the 1-byte header of the
																						 * extension element
																						 */
				+ len + 3 /* padding */;

		byte[] newBuffer;
		int newPayloadOffset;
		if (getBuffer().length >= maxRequiredLength) {
			// We don't need a new buffer.
			newBuffer = getBuffer();

			if ((getOffset() + getHeaderLength()) >= (maxRequiredLength - getPayloadLength())) {
				// If region A (see above) is enough to accommodate the new
				// packet, then keep the payload where it is.
				newPayloadOffset = getPayloadOffset();
			} else {
				// Otherwise, we have to use region D. To do so, move the
				// payload to the right.
				newPayloadOffset = getBuffer().length - payloadLength;
				System.arraycopy(getBuffer(), getPayloadOffset(), getBuffer(), newPayloadOffset, payloadLength);
			}
		} else {
			// We need a new buffer. We will place the payload to the very right.
			newBuffer = new byte[maxRequiredLength];
			newPayloadOffset = newBuffer.length - payloadLength;
			System.arraycopy(getBuffer(), getPayloadOffset(), newBuffer, newPayloadOffset, payloadLength);
		}

		// By now we have the payload in a position which leaves enough space
		// for the whole new header.
		// Next, we are going to construct a new header + extensions (including
		// the one we are adding) at offset 0, and once finished, we will move
		// them to the correct offset.

		int newHeaderLength = extHeaderOffset;
		// The bytes in the header extensions, excluding the (0xBEDE, length)
		// field and any padding.
		int extensionBytes = 0;
		if (extensionBit) {
			// (0xBEDE, length)
			newHeaderLength += 4;

			// We can't find the actual length without an iteration because
			// of padding. It is safe to iterate, because we have not yet
			// modified the header (we only might have moved the offset right)
			HeaderExtensions hes = getHeaderExtensions();
			while (hes.hasNext()) {
				HeaderExtension he = hes.next();
				// 1 byte for id/len + data
				extensionBytes += 1 + he.getExtLength();
			}

			newHeaderLength += extensionBytes;
		}

		// Copy the header (and extensions, excluding padding, if there are any)
		System.arraycopy(getBuffer(), getOffset(), newBuffer, 0, newHeaderLength);

		if (!extensionBit) {
			// If the original packet didn't have any extensions, we need to
			// add the extension header (RFC 5285):
			// 0 1 2 3
			// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			// | 0xBE | 0xDE | length |
			// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			writeShort(newBuffer, extHeaderOffset, (short) 0xBEDE);
			// We will set the length field later.
			newHeaderLength += 4;
		}

		// Finally we get to add our extension.
		newBuffer[newHeaderLength++] = (byte) ((id & 0x0f) << 4 | (len - 1) & 0x0f);
		extensionBytes++;

		// This is where the data of the extension that we add begins. We just
		// skip 'len' bytes, and let the caller fill them in. We have to go
		// back one byte, because newHeaderLength already moved.
		int extensionDataOffset = newHeaderLength - 1;
		newHeaderLength += len;
		extensionBytes += len;

		int paddingBytes = (4 - (extensionBytes % 4)) % 4;
		for (int i = 0; i < paddingBytes; i++) {
			// Set the padding to 0 (we have to do this because we may be
			// reusing a buffer).
			newBuffer[newHeaderLength++] = 0;
		}

		writeShort(newBuffer, extHeaderOffset + 2, (short) ((extensionBytes + paddingBytes) / 4));

		// Now we have the new header, with the added header extension and with
		// the correct padding, in newBuffer at offset 0. Lets move it to the
		// correct place (right before the payload).
		int newOffset = newPayloadOffset - newHeaderLength;
		if (newOffset != 0) {
			System.arraycopy(newBuffer, 0, newBuffer, newOffset, newHeaderLength);
		}

		// All that is left to do is update the RawPacket state.
		setBuffer(newBuffer);
		this.setOffset(newOffset);
		this.setLength(newHeaderLength + payloadLength);

		// ... and set the extension bit.
		setExtensionBit(true);

		// Setup the single HeaderExtension instance of this RawPacket and
		// return it.
		HeaderExtension he = getHeaderExtensions().headerExtension;
		he.setOffset(getOffset() + extensionDataOffset);
		he.setLength(len + 1);
		return he;
	}

	/**
	 * Returns a map binding CSRC IDs to audio levels as reported by the remote
	 * party that sent this packet.
	 *
	 * @param csrcExtID the ID of the extension that's transporting csrc audio
	 *                  levels in the session that this <tt>RawPacket</tt> belongs
	 *                  to.
	 *
	 * @return an array representing a map binding CSRC IDs to audio levels as
	 *         reported by the remote party that sent this packet. The entries of
	 *         the map are contained in consecutive elements of the returned array
	 *         where elements at even indices stand for CSRC IDs and elements at odd
	 *         indices stand for the associated audio levels
	 */
	public long[] extractCsrcAudioLevels(byte csrcExtID) {
		if (!getExtensionBit() || (getExtensionLength() == 0))
			return null;

		int csrcCount = getCsrcCount();

		if (csrcCount == 0)
			return null;

		/*
		 * XXX The guideline which is also supported by Google and recommended for
		 * Android is that single-dimensional arrays should be preferred to
		 * multi-dimensional arrays in Java because the former take less space than the
		 * latter and are thus more efficient in terms of memory and garbage collection.
		 */
		long[] csrcLevels = new long[csrcCount * 2];

		// first extract the csrc IDs
		for (int i = 0, csrcStartIndex = getOffset() + FIXED_HEADER_SIZE; i < csrcCount; i++, csrcStartIndex += 4) {
			int csrcLevelsIndex = 2 * i;

			csrcLevels[csrcLevelsIndex] = readUint32AsLong(csrcStartIndex);
			/*
			 * The audio levels generated by Jitsi are not in accord with the respective
			 * specification, they are backwards with respect to the value domain. Which
			 * means that the audio level generated from a muted audio source is 0/zero.
			 */
			csrcLevels[csrcLevelsIndex + 1] = getCsrcAudioLevel(csrcExtID, i, (byte) 0);
		}

		return csrcLevels;
	}

	/**
	 * Returns the list of CSRC IDs, currently encapsulated in this packet.
	 *
	 * @return an array containing the list of CSRC IDs, currently encapsulated in
	 *         this packet.
	 */
	public long[] extractCsrcList() {
		int csrcCount = getCsrcCount();
		long[] csrcList = new long[csrcCount];

		for (int i = 0, csrcStartIndex = getOffset() + FIXED_HEADER_SIZE; i < csrcCount; i++, csrcStartIndex += 4) {
			csrcList[i] = readInt(csrcStartIndex);
		}

		return csrcList;
	}

	/**
	 * Extracts the source audio level reported by the remote party which sent this
	 * packet and carried in this packet.
	 *
	 * @param ssrcExtID the ID of the extension that's transporting ssrc audio
	 *                  levels in the session that this <tt>RawPacket</tt> belongs
	 *                  to
	 * @return the source audio level reported by the remote party which sent this
	 *         packet and carried in this packet or a negative value if this packet
	 *         contains no extension such as the specified by <tt>ssrcExtID</tt>
	 */
	public byte extractSsrcAudioLevel(byte ssrcExtID) {
		/*
		 * The method getCsrcAudioLevel(byte, int) is implemented with the awareness
		 * that there may be a flag bit V with a value other than 0.
		 */
		/*
		 * The audio levels sent by Google Chrome are in accord with the specification
		 * i.e. the audio level generated from a muted audio source is 127 and the
		 * values are non-negative. If there is no source audio level in this packet,
		 * return a negative value.
		 */
		return getCsrcAudioLevel(ssrcExtID, 0, Byte.MIN_VALUE);
	}

	/**
	 * Returns the index of the element in this packet's buffer where the content of
	 * the header with the specified <tt>extensionID</tt> starts.
	 *
	 * @param extensionID the ID of the extension whose content we are looking for.
	 *
	 * @return the index of the first byte of the content of the extension with the
	 *         specified <tt>extensionID</tt> or -1 if no such extension was found.
	 */
	private int findExtension(int extensionID) {
		if (!getExtensionBit() || getExtensionLength() == 0)
			return 0;

		int extOffset = getOffset() + FIXED_HEADER_SIZE + getCsrcCount() * 4 + EXT_HEADER_SIZE;

		int extensionEnd = extOffset + getExtensionLength();
		int extHdrLen = getExtensionHeaderLength();

		if (extHdrLen != 1 && extHdrLen != 2) {
			return -1;
		}

		while (extOffset < extensionEnd) {
			int currType = -1;
			int currLen = -1;

			if (extHdrLen == 1) {
				// short header. type is in the lefter 4 bits and length is on
				// the right; like this:
				// 0
				// 0 1 2 3 4 5 6 7
				// +-+-+-+-+-+-+-+-+
				// | ID | len |
				// +-+-+-+-+-+-+-+-+

				currType = getBuffer()[extOffset] >> 4;
				currLen = (getBuffer()[extOffset] & 0x0F) + 1; // add one as per 5285

				// now skip the header
				extOffset++;
			} else {
				// long header. type is in the first byte and length is in the
				// second
				// 0 1
				// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// | ID | length |
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				currType = getBuffer()[extOffset];
				currLen = getBuffer()[extOffset + 1];

				// now skip the header
				extOffset += 2;
			}

			if (currType == extensionID) {
				return extOffset;
			}

			extOffset += currLen;
		}

		return -1;
	}

	/**
	 * Returns the CSRC level at the specified index or <tt>defaultValue</tt> if
	 * there was no level at that index.
	 *
	 * @param csrcExtID the ID of the extension that's transporting csrc audio
	 *                  levels in the session that this <tt>RawPacket</tt> belongs
	 *                  to.
	 * @param index     the sequence number of the CSRC audio level extension to
	 *                  return.
	 *
	 * @return the CSRC audio level at the specified index of the csrc audio level
	 *         option or <tt>0</tt> if there was no level at that index.
	 */
	private byte getCsrcAudioLevel(byte csrcExtID, int index, byte defaultValue) {
		byte level = defaultValue;

		try {
			if (getExtensionBit() && getExtensionLength() != 0) {
				int levelsStart = findExtension(csrcExtID);

				if (levelsStart != -1) {
					int levelsCount = getLengthForExtension(levelsStart);

					if (levelsCount < index) {
						// apparently the remote side sent more CSRCs than levels.

						// ... yeah remote sides do that now and then ...
					} else {
						level = (byte) (0x7F & getBuffer()[levelsStart + index]);
					}
				}
			}
		} catch (ArrayIndexOutOfBoundsException e) {
			// While ideally we should check the bounds everywhere and not
			// attempt to access the packet's buffer at invalid indexes, there
			// are too many places where it could inadvertently happen. It's
			// safer to return the default value than to risk killing a thread
			// which may not expect this.
			level = defaultValue;
		}

		return level;
	}

	/**
	 * Returns the number of CSRC identifiers currently included in this packet.
	 *
	 * @return the CSRC count for this <tt>RawPacket</tt>.
	 */
	public int getCsrcCount() {
		return getCsrcCount(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Returns the number of CSRC identifiers currently included in this packet.
	 *
	 * @return the CSRC count for this <tt>RawPacket</tt>.
	 */
	public static int getCsrcCount(byte[] buffer, int offset, int length) {
		int cc = buffer[offset] & 0x0f;
		if (FIXED_HEADER_SIZE + cc * 4 > length)
			cc = 0;
		return cc;
	}

	/**
	 * Returns <tt>true</tt> if the extension bit of this packet has been set and
	 * <tt>false</tt> otherwise.
	 *
	 * @return <tt>true</tt> if the extension bit of this packet has been set and
	 *         <tt>false</tt> otherwise.
	 */
	public boolean getExtensionBit() {
		return getExtensionBit(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Returns <tt>true</tt> if the extension bit of this packet has been set and
	 * <tt>false</tt> otherwise.
	 *
	 * @return <tt>true</tt> if the extension bit of this packet has been set and
	 *         <tt>false</tt> otherwise.
	 */
	public static boolean getExtensionBit(byte[] buffer, int offset, int length) {
		return (buffer[offset] & 0x10) == 0x10;
	}

	/**
	 * Returns the length of the extension header being used in this packet or
	 * <tt>-1</tt> in case there were no extension headers here or we didn't
	 * understand the kind of extension being used.
	 *
	 * @return the length of the extension header being used in this packet or
	 *         <tt>-1</tt> in case there were no extension headers here or we didn't
	 *         understand the kind of extension being used.
	 */
	private int getExtensionHeaderLength() {
		if (!getExtensionBit())
			return -1;

		// the type of the extension header comes right after the RTP header and
		// the CSRC list.
		int extLenIndex = getOffset() + FIXED_HEADER_SIZE + getCsrcCount() * 4;

		// 0xBEDE means short extension header.
		if (getBuffer()[extLenIndex] == (byte) 0xBE && getBuffer()[extLenIndex + 1] == (byte) 0xDE)
			return 1;

		// 0x100 means a two-byte extension header.
		if (getBuffer()[extLenIndex] == (byte) 0x10 && (getBuffer()[extLenIndex + 1] >> 4) == 0)
			return 2;

		return -1;
	}

	/**
	 * Returns the length of the extensions currently added to this packet.
	 *
	 * @return the length of the extensions currently added to this packet.
	 */
	public int getExtensionLength() {
		return getExtensionLength(getBuffer(), getOffset(), getLength());
	}

	/**
	 * @return the iterator over this {@link RawPacket}'s RTP header extensions.
	 */
	public HeaderExtensions getHeaderExtensions() {
		if (headerExtensions == null) {
			headerExtensions = new HeaderExtensions();
		}
		headerExtensions.reset();
		return headerExtensions;
	}

	/**
	 * Returns the length of the extensions currently added to this packet.
	 *
	 * @return the length of the extensions currently added to this packet.
	 */
	public static int getExtensionLength(byte[] buffer, int offset, int length) {
		if (!getExtensionBit(buffer, offset, length))
			return 0;

		// TODO should we verify the "defined by profile" field here (0xBEDE)?

		// The extension length comes after the RTP header, the CSRC list, and
		// two bytes in the extension header called "defined by profile".
		int extLenIndex = offset + FIXED_HEADER_SIZE + getCsrcCount(buffer, offset, length) * 4 + 2;

		int len = ((buffer[extLenIndex] << 8) | (buffer[extLenIndex + 1] & 0xFF)) * 4;

		if (len < 0
				|| len > (length - FIXED_HEADER_SIZE - EXT_HEADER_SIZE - getCsrcCount(buffer, offset, length) * 4)) {
			// This is not a valid length. Together with the rest of the
			// header it exceeds the packet length. So be safe and assume
			// that there is no extension.
			len = 0;
		}

		return len;
	}

	/**
	 * Gets the bitmap/flag mask that specifies the set of boolean attributes
	 * enabled for this <tt>RawPacket</tt>.
	 *
	 * @return the bitmap/flag mask that specifies the set of boolean attributes
	 *         enabled for this <tt>RawPacket</tt>
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Return the define by profile part of the extension header.
	 * 
	 * @return the starting two bytes of extension header.
	 */
	public int getHeaderExtensionType() {
		if (!getExtensionBit())
			return 0;

		return readUint16AsInt(getOffset() + FIXED_HEADER_SIZE + getCsrcCount() * 4);
	}

	/**
	 * Get RTP header length from a RTP packet
	 *
	 * @return RTP header length from source RTP packet
	 */
	public int getHeaderLength() {
		return getHeaderLength(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP header length from a RTP packet
	 *
	 * @return RTP header length from source RTP packet
	 */
	public static int getHeaderLength(byte[] buffer, int offset, int length) {
		int headerLength = FIXED_HEADER_SIZE + 4 * getCsrcCount(buffer, offset, length);

		// Make sure that the header length doesn't exceed the packet length.
		if (headerLength > length) {
			headerLength = length;
		}

		if (getExtensionBit(buffer, offset, length)) {
			// Make sure that the header length doesn't exceed the packet
			// length.
			if (headerLength + EXT_HEADER_SIZE <= length) {
				headerLength += EXT_HEADER_SIZE + getExtensionLength(buffer, offset, length);
			}
		}

		return headerLength;
	}

	/**
	 * Returns the length of the header extension that is carrying the content
	 * starting at <tt>contentStart</tt>. In other words this method checks the size
	 * of extension headers in this packet and then either returns the value of the
	 * byte right before <tt>contentStart</tt> or its lower 4 bits. This is a very
	 * basic method so if you are using it - make sure u know what you are doing.
	 *
	 * @param contentStart the index of the first element of the content of the
	 *                     extension whose size we are trying to obtain.
	 *
	 * @return the length of the extension carrying the content starting at
	 *         <tt>contentStart</tt>.
	 */
	private int getLengthForExtension(int contentStart) {
		int hdrLen = getExtensionHeaderLength();

		if (hdrLen == 1)
			return (getBuffer()[contentStart - 1] & 0x0F) + 1;
		else
			return getBuffer()[contentStart - 1];
	}

	/**
	 * Gets the value of the "version" field of an RTP packet.
	 * 
	 * @return the value of the RTP "version" field.
	 */
	public int getVersion() {
		return getVersion(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP padding size from a RTP packet
	 *
	 * @return RTP padding size from source RTP packet
	 */
	public int getPaddingSize() {
		return getPaddingSize(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP padding size from a RTP packet
	 *
	 * @return RTP padding size from source RTP packet
	 */
	public static int getPaddingSize(byte[] buf, int off, int len) {
		if ((buf[off] & 0x20) == 0) {
			return 0;
		} else {
			// The last octet of the padding contains a count of how many
			// padding octets should be ignored, including itself.

			// XXX It's an 8-bit unsigned number.
			return 0xFF & buf[off + len - 1];
		}
	}

	/**
	 * Get the RTP payload (bytes) of this RTP packet.
	 *
	 * @return an array of <tt>byte</tt>s which represents the RTP payload of this
	 *         RTP packet
	 */
	public byte[] getPayload() {
		// FIXME The payload includes the padding at the end. Do we really want
		// it though? We are currently keeping the implementation as it is for
		// compatibility with existing code.
		return readRegion(getHeaderLength(), getPayloadLength());
	}

	/**
	 * Get RTP payload length from a RTP packet
	 *
	 * @return RTP payload length from source RTP packet
	 */
	public int getPayloadLength(boolean removePadding) {
		return getPayloadLength(getBuffer(), getOffset(), getLength(), removePadding);
	}

	/**
	 * Get RTP payload length from a RTP packet
	 *
	 * @return RTP payload length from source RTP packet
	 */
	public int getPayloadLength() {
		return getPayloadLength(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP payload length from a RTP packet
	 *
	 * @return RTP payload length from source RTP packet
	 */
	public static int getPayloadLength(byte[] buffer, int offset, int length) {
		return getPayloadLength(buffer, offset, length, false);
	}

	/**
	 * Get RTP payload length from a RTP packet
	 *
	 * @return RTP payload length from source RTP packet
	 */
	public static int getPayloadLength(byte[] buffer, int offset, int length, boolean removePadding) {
		int lenHeader = getHeaderLength(buffer, offset, length);
		if (lenHeader < 0) {
			return -1;
		}

		int len = length - lenHeader;

		if (removePadding) {
			int szPadding = getPaddingSize(buffer, offset, length);
			if (szPadding < 0) {
				return -1;
			}

			len -= szPadding;
		}
		return len;
	}

	/**
	 * Get the RTP payload offset of an RTP packet.
	 *
	 * @return the RTP payload offset of an RTP packet.
	 */
	public int getPayloadOffset() {
		return getPayloadOffset(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get the RTP payload offset of an RTP packet.
	 *
	 * @return the RTP payload offset of an RTP packet.
	 */
	public static int getPayloadOffset(byte[] buffer, int offset, int length) {
		return offset + getHeaderLength(buffer, offset, length);
	}

	/**
	 * Get RTP payload type from a RTP packet
	 *
	 * @return RTP payload type of source RTP packet
	 */
	public byte getPayloadType() {
		return (byte) getPayloadType(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP payload type from a RTP packet
	 *
	 * @return RTP payload type of source RTP packet, or -1 in case of an error.
	 */
	public static int getPayloadType(byte[] buf, int off, int len) {
		if (buf == null || buf.length < off + len || len < 2) {
			return -1;
		}

		return (buf[off + 1] & 0x7F);
	}

	/**
	 * Get RTP payload type from a RTP packet
	 *
	 * @return RTP payload type of source RTP packet, or -1 in case of an error.
	 */
	public static int getPayloadType(RawPacket pkt) {
		if (pkt == null) {
			return -1;
		}

		return getPayloadType(pkt.getBuffer(), pkt.getOffset(), pkt.getLength());
	}

	/**
	 * Get RTCP SSRC from a RTCP packet
	 *
	 * @return RTP SSRC from source RTP packet
	 */
	public long getRTCPSSRC() {
		return getRTCPSSRC(this);
	}

	/**
	 * Gets the packet type of this RTCP packet.
	 *
	 * @return the packet type of this RTCP packet.
	 */
	public int getRTCPPacketType() {
		return 0xff & getBuffer()[getOffset() + 1];
	}

	/**
	 * Get RTP sequence number from a RTP packet
	 *
	 * @return RTP sequence num from source packet
	 */
	public int getSequenceNumber() {
		return getSequenceNumber(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP sequence number from a RTP packet
	 *
	 * @return RTP sequence num from source packet
	 */
	public static int getSequenceNumber(byte[] buffer, int offset, int length) {
		return readUint16AsInt(buffer, offset + 2);
	}

	/**
	 * Gets the RTP sequence number from a RTP packet.
	 *
	 * @param baf the {@link ByteArrayBuffer} that contains the RTP packet.
	 *
	 * @return the RTP sequence number from a RTP packet.
	 */
	public static int getSequenceNumber(RawPacket packet) {
		if (packet == null) {
			return -1;
		}

		return getSequenceNumber(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Set sequence number for an RTP buffer
	 */
	public static void setSequenceNumber(byte[] buffer, int offset, int seq) {
		writeShort(buffer, offset + 2, (short) seq);
	}

	/**
	 * Sets the sequence number of an RTP packet.
	 *
	 * @param baf       the {@link ByteArrayBuffer} that contains the RTP packet.
	 * @param dstSeqNum the sequence number to set in the RTP packet.
	 */
	public static void setSequenceNumber(RawPacket packet, int dstSeqNum) {
		if (packet == null) {
			return;
		}

		setSequenceNumber(packet.getBuffer(), packet.getOffset(), dstSeqNum);
	}

	/**
	 * Set the RTP timestamp for an RTP buffer.
	 *
	 * @param buf the <tt>byte</tt> array that holds the RTP packet.
	 * @param off the offset in <tt>buffer</tt> at which the actual RTP data begins.
	 * @param len the number of <tt>byte</tt>s in <tt>buffer</tt> which constitute
	 *            the actual RTP data.
	 * @param ts  the timestamp to set in the RTP buffer.
	 */
	public static void setTimestamp(byte[] buf, int off, int len, long ts) {
		writeInt(buf, off + 4, (int) ts);
	}

	/**
	 * Sets the RTP timestamp of an RTP packet.
	 *
	 * param baaf the {@link ByteArrayBuffer} that contains the RTP packet.
	 * 
	 * @param ts the timestamp to set in the RTP packet.
	 */
	public static void setTimestamp(RawPacket packet, long ts) {
		if (packet == null) {
			return;
		}

		setTimestamp(packet.getBuffer(), packet.getOffset(), packet.getLength(), ts);
	}

	/**
	 * Get SRTCP sequence number from a SRTCP packet
	 *
	 * @param authTagLen authentication tag length
	 * @return SRTCP sequence num from source packet
	 */
	public int getSRTCPIndex(int authTagLen) {
		return getSRTCPIndex(this, authTagLen);
	}

	/**
	 * Get SRTCP sequence number from a SRTCP packet
	 *
	 * @param authTagLen authentication tag length
	 * @return SRTCP sequence num from source packet
	 */
	public static int getSRTCPIndex(RawPacket packet, int authTagLen) {
		int authTagOffset = packet.getLength() - (4 + authTagLen);
		return readInt(packet.getBuffer(), packet.getOffset() + authTagOffset);
	}

	/**
	 * Get RTP SSRC from a RTP packet
	 *
	 * @return RTP SSRC from source RTP packet
	 */
	public int getSSRC() {
		return getSSRC(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Get RTP SSRC from a RTP packet
	 *
	 * @return RTP SSRC from source RTP packet
	 */
	public static int getSSRC(byte[] buffer, int offset, int length) {
		return readInt(buffer, offset + 8);
	}

	/**
	 * Get RTP SSRC from a RTP packet
	 */
	public static int getSSRC(RawPacket packet) {
		return getSSRC(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Returns a {@code long} representation of the SSRC of this RTP packet.
	 * 
	 * @return a {@code long} representation of the SSRC of this RTP packet.
	 */
	public long getSSRCAsLong() {
		return getSSRCAsLong(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Returns a {@code long} representation of the SSRC of this RTP packet.
	 *
	 * @return a {@code long} representation of the SSRC of this RTP packet.
	 */
	public static long getSSRCAsLong(byte[] buffer, int offset, int length) {
		return getSSRC(buffer, offset, length) & 0xffffffffL;
	}

	/**
	 * Returns the timestamp for this RTP <tt>RawPacket</tt>.
	 *
	 * @return the timestamp for this RTP <tt>RawPacket</tt>.
	 */
	public long getTimestamp() {
		return getTimestamp(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Gets the RTP timestamp for an RTP buffer.
	 *
	 * @param buf the <tt>byte</tt> array that holds the RTP packet.
	 * @param off the offset in <tt>buffer</tt> at which the actual RTP data begins.
	 * @param len the number of <tt>byte</tt>s in <tt>buffer</tt> which constitute
	 *            the actual RTP data.
	 * @return the timestamp in the RTP buffer.
	 */
	public static long getTimestamp(byte[] buf, int off, int len) {
		return readUint32AsLong(buf, off + 4);
	}

	/**
	 * Gets the RTP timestamp for an RTP buffer.
	 *
	 * @param baf the {@link ByteArrayBuffer} that contains the RTP packet.
	 * @return the timestamp in the RTP buffer.
	 */
	public static long getTimestamp(RawPacket packet) {
		if (packet == null) {
			return -1;
		}

		return getTimestamp(packet.getBuffer(), packet.getOffset(), packet.getLength());
	}

	/**
	 * Perform checks on the packet represented by this instance and return
	 * <tt>true</tt> if it is found to be invalid. A return value of <tt>false</tt>
	 * does not necessarily mean that the packet is valid.
	 *
	 * @return <tt>true</tt> if the RTP/RTCP packet represented by this instance is
	 *         found to be invalid, <tt>false</tt> otherwise.
	 */
	public boolean isInvalid() {
		return isInvalid(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Test whether the RTP Marker bit is set
	 *
	 * @return whether the RTP Marker bit is set
	 */
	public boolean isPacketMarked() {
		return isPacketMarked(getBuffer(), getOffset(), getLength());
	}

	/**
	 * Removes the extension from the packet and its header.
	 */
	public void removeExtension() {
		if (!getExtensionBit())
			return;

		int payloadOffset = getOffset() + getHeaderLength();

		int extHeaderLen = getExtensionLength() + EXT_HEADER_SIZE;

		System.arraycopy(getBuffer(), payloadOffset, getBuffer(), payloadOffset - extHeaderLen, getPayloadLength());

		this.setLength(this.getLength() - extHeaderLen);

		setExtensionBit(false);
	}

	/**
	 * @param buffer the buffer to set
	 */
	public void setBuffer(byte[] buffer) {
		super.setBuffer(buffer);
		headerExtensions = new HeaderExtensions();
	}

	/**
	 * Replaces the existing CSRC list (even if empty) with <tt>newCsrcList</tt> and
	 * updates the CC (CSRC count) field of this <tt>RawPacket</tt> accordingly.
	 *
	 * @param newCsrcList the list of CSRC identifiers that we'd like to set for
	 *                    this <tt>RawPacket</tt>.
	 */
	public void setCsrcList(long[] newCsrcList) {
		int newCsrcCount = newCsrcList.length;
		byte[] csrcBuff = new byte[newCsrcCount * 4];
		int csrcOffset = 0;

		for (int i = 0; i < newCsrcList.length; i++) {
			long csrc = newCsrcList[i];

			writeInt(csrcBuff, csrcOffset, (int) csrc);
			csrcOffset += 4;
		}

		int oldCsrcCount = getCsrcCount();

		byte[] oldBuffer = this.getBuffer();

		// the new buffer needs to be bigger than the new one in order to
		// accommodate the list of CSRC IDs (unless there were more of them
		// previously than after setting the new list).
		byte[] newBuffer = new byte[getLength() + getOffset() + csrcBuff.length - oldCsrcCount * 4];

		// copy the part up to the CSRC list
		System.arraycopy(oldBuffer, 0, newBuffer, 0, getOffset() + FIXED_HEADER_SIZE);

		// copy the new CSRC list
		System.arraycopy(csrcBuff, 0, newBuffer, getOffset() + FIXED_HEADER_SIZE, csrcBuff.length);

		// now copy the payload from the old buff and make sure we don't copy
		// the CSRC list if there was one in the old packet
		int payloadOffsetForOldBuff = getOffset() + FIXED_HEADER_SIZE + oldCsrcCount * 4;

		int payloadOffsetForNewBuff = getOffset() + FIXED_HEADER_SIZE + newCsrcCount * 4;

		System.arraycopy(oldBuffer, payloadOffsetForOldBuff, newBuffer, payloadOffsetForNewBuff,
				getLength() - payloadOffsetForOldBuff);

		// set the new CSRC count
		newBuffer[getOffset()] = (byte) ((newBuffer[getOffset()] & 0xF0) | newCsrcCount);

		setBuffer(newBuffer);
		this.setLength(payloadOffsetForNewBuff + getLength() - payloadOffsetForOldBuff - getOffset());
	}

	/**
	 * Raises the extension bit of this packet is <tt>extBit</tt> is <tt>true</tt>
	 * or set it to <tt>0</tt> if <tt>extBit</tt> is <tt>false</tt>.
	 *
	 * @param extBit the flag that indicates whether we are to set or clear the
	 *               extension bit of this packet.
	 */
	private void setExtensionBit(boolean extBit) {
		if (extBit)
			getBuffer()[getOffset()] |= 0x10;
		else
			getBuffer()[getOffset()] &= 0xEF;
	}

	/**
	 * Sets the bitmap/flag mask that specifies the set of boolean attributes
	 * enabled for this <tt>RawPacket</tt>.
	 *
	 * @param flags the bitmap/flag mask that specifies the set of boolean
	 *              attributes enabled for this <tt>RawPacket</tt>
	 */
	public void setFlags(int flags) {
		this.flags = flags;
	}

	/**
	 * Sets or resets the marker bit of this packet according to the <tt>marker</tt>
	 * parameter.
	 * 
	 * @param marker <tt>true</tt> if we are to raise the marker bit and
	 *               <tt>false</tt> otherwise.
	 */
	public void setMarker(boolean marker) {
		if (marker) {
			getBuffer()[getOffset() + 1] |= (byte) 0x80;
		} else {
			getBuffer()[getOffset() + 1] &= (byte) 0x7F;
		}
	}

	/**
	 * Sets the payload type of this packet.
	 *
	 * @param payload the RTP payload type describing the content of this packet.
	 */
	public void setPayloadType(byte payload) {
		// this is supposed to be a 7bit payload so make sure that the leftmost
		// bit is 0 so that we don't accidentally overwrite the marker.
		payload &= (byte) 0x7F;

		getBuffer()[getOffset() + 1] = (byte) ((getBuffer()[getOffset() + 1] & 0x80) | payload);
	}

	/**
	 * Set the RTP sequence number of an RTP packet
	 * 
	 * @param seq the sequence number to set (only the least-significant 16bits are
	 *            used)
	 */
	public void setSequenceNumber(int seq) {
		RawPacket.setSequenceNumber(getBuffer(), getOffset(), seq);
	}

	/**
	 * Set the SSRC of this packet
	 * 
	 * @param ssrc SSRC to set
	 */
	public void setSSRC(long ssrc) {
		writeInt(8, (int) ssrc);
	}

	/**
	 * Set the timestamp value of the RTP Packet
	 *
	 * @param timestamp : the RTP Timestamp
	 */
	public void setTimestamp(long timestamp) {
		setTimestamp(getBuffer(), getOffset(), getLength(), timestamp);
	}

	/**
	 * Gets the OSN value of an RTX packet.
	 *
	 * @return the OSN value of an RTX packet.
	 */
	public int getOriginalSequenceNumber() {
		return readUint16AsInt(getBuffer(), getOffset() + getHeaderLength());
	}

	/**
	 * Sets the OSN value of an RTX packet.
	 *
	 * @param sequenceNumber the new OSN value of this RTX packet.
	 */
	public void setOriginalSequenceNumber(int sequenceNumber) {
		writeShort(getHeaderLength(), (short) sequenceNumber);
	}

	/**
	 * Sets the padding length for this RTP packet.
	 *
	 * @param len the padding length.
	 * @return the number of bytes that were written, or -1 in case of an error.
	 */
	public boolean setPaddingSize(int len) {
		if (getBuffer() == null || getBuffer().length < getOffset() + FIXED_HEADER_SIZE + len || len < 0
				|| len > 0xFF) {
			return false;
		}

		// Set the padding bit.
		getBuffer()[getOffset()] |= 0x20;
		getBuffer()[getOffset() + getLength() - 1] = (byte) len;

		return true;
	}

	/**
	 * Sets the RTP version in this RTP packet.
	 *
	 * @return the number of bytes that were written, or -1 in case of an error.
	 */
	public boolean setVersion() {
		if (isInvalid()) {
			return false;
		}

		getBuffer()[getOffset()] |= 0x80;
		return true;
	}

	/**
	 * Whether to skip packet statistics.
	 * 
	 * @return returns true if we want to skip stats for this packet.
	 */
	public boolean isSkipStats() {
		return skipStats;
	}

	/**
	 * Changes the skipStats flag.
	 * 
	 * @param skipStats the new value.
	 */
	public void setSkipStats(boolean skipStats) {
		this.skipStats = skipStats;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		// Note: this will not print meaningful values unless the packet is an
		// RTP packet.
		StringBuilder sb = new StringBuilder("RawPacket[off=").append(getOffset()).append(", len=").append(getLength())
				.append(", PT=").append(getPayloadType()).append(", SSRC=").append(getSSRCAsLong()).append(", seq=")
				.append(getSequenceNumber()).append(", M=").append(isPacketMarked()).append(", X=")
				.append(getExtensionBit()).append(", TS=").append(getTimestamp()).append(", hdrLen=")
				.append(getHeaderLength()).append(", payloadLen=").append(getPayloadLength()).append(", paddingLen=")
				.append(getPaddingSize()).append(", extLen=").append(getExtensionLength()).append(']');

		return sb.toString();
	}

	/**
	 * Returns the delta between two RTP sequence numbers, taking into account
	 * rollover. This will return the 'shortest' delta between the two sequence
	 * numbers in the form of the number you'd add to b to get a. e.g.:
	 * getSequenceNumberDelta(1, 10) -&gt; -9 (10 + -9 = 1)
	 * getSequenceNumberDelta(1, 65530) -&gt; 7 (65530 + 7 = 1)
	 * 
	 * @return the delta between two RTP sequence numbers (modulo 2^16).
	 */
	public static int getSequenceNumberDelta(int a, int b) {
		int diff = a - b;

		if (diff < -(1 << 15)) {
			diff += 1 << 16;
		} else if (diff > 1 << 15) {
			diff -= 1 << 16;
		}

		return diff;
	}

	/**
	 * Returns whether or not seqNumOne is 'older' than seqNumTwo, taking rollover
	 * into account
	 * 
	 * @param seqNumOne
	 * @param seqNumTwo
	 * @return true if seqNumOne is 'older' than seqNumTwo
	 */
	public static boolean isOlderSequenceNumberThan(int seqNumOne, int seqNumTwo) {
		return getSequenceNumberDelta(seqNumOne, seqNumTwo) < 0;
	}

	/**
	 * Returns result of the subtraction of one RTP sequence number from another
	 * (modulo 2^16).
	 * 
	 * @return result of the subtraction of one RTP sequence number from another
	 *         (modulo 2^16).
	 */
	public static int subtractNumber(int a, int b) {
		return as16Bits(a - b);
	}

	/**
	 * Apply a delta to a given sequence number and return the result (taking
	 * rollover into account)
	 * 
	 * @param startingSequenceNumber the starting sequence number
	 * @param delta                  the delta to be applied
	 * @return the sequence number result from doing startingSequenceNumber + delta
	 */
	public static int applySequenceNumberDelta(int startingSequenceNumber, int delta) {
		return (startingSequenceNumber + delta) & 0xFFFF;
	}

	/**
	 * A {@link Comparator} implementation for unsigned 16-bit {@link Integer}s.
	 * Compares {@code a} and {@code b} inside the [0, 2^16] ring; {@code a} is
	 * considered smaller than {@code b} if it takes a smaller number to reach from
	 * {@code a} to {@code b} than the other way round.
	 *
	 * IMPORTANT: This is a valid {@link Comparator} implementation only when used
	 * for subsets of [0, 2^16) which don't span more than 2^15 elements.
	 *
	 * E.g. it works for: [0, 2^15-1] and ([50000, 2^16) u [0, 10000]) Doesn't work
	 * for: [0, 2^15] and ([0, 2^15-1] u {2^16-1}) and [0, 2^16)
	 */
	public static final Comparator<? super Integer> sequenceNumberComparator = new Comparator<Integer>() {
		@Override
		public int compare(Integer a, Integer b) {
			if (a.equals(b)) {
				return 0;
			} else if (a > b) {
				if (a - b < 0x10000) {
					return 1;
				} else {
					return -1;
				}
			} else // a < b
			{
				if (b - a < 0x10000) {
					return -1;
				} else {
					return 1;
				}
			}
		}
	};

	/**
	 * Returns the difference between two RTP timestamps.
	 * 
	 * @return the difference between two RTP timestamps.
	 */
	public static long rtpTimestampDiff(long a, long b) {
		long diff = a - b;
		if (diff < -(1L << 31)) {
			diff += 1L << 32;
		} else if (diff > 1L << 31) {
			diff -= 1L << 32;
		}

		return diff;
	}

	/**
	 * Returns whether or not the first given timestamp is newer than the second
	 * 
	 * @param a
	 * @param b
	 * @return true if a is newer than b, false otherwise
	 */
	public static boolean isNewerTimestampThan(long a, long b) {
		return rtpTimestampDiff(a, b) > 0;
	}

	/**
	 * @return the header extension of this {@link RawPacket} with the given ID, or
	 *         null if the packet doesn't have one. WARNING: This method should not
	 *         be used while iterating over the extensions with
	 *         {@link #getHeaderExtensions()}, because it uses the same iterator.
	 * @param id
	 */
	public HeaderExtension getHeaderExtension(byte id) {
		HeaderExtensions hes = getHeaderExtensions();
		while (hes.hasNext()) {
			HeaderExtension he = hes.next();
			if (he.getExtId() == id) {
				return he;
			}
		}
		return null;
	}

	/**
	 * Represents an RTP header extension with the RFC5285 one-byte header:
	 * 
	 * <pre>
	 * {@code
	 * 0
	 * 0 1 2 3 4 5 6 7
	 * +-+-+-+-+-+-+-+-+
	 * |  ID   |  len  |
	 * +-+-+-+-+-+-+-+-+
	 * }
	 * </pre>
	 */
	public class HeaderExtension extends ByteBuffer {
		HeaderExtension() {
			super(RawPacket.this.getBuffer(), 0, 0);
		}

		/**
		 * @return the ID field of this extension.
		 */
		public int getExtId() {
			if (super.getLength() <= 0)
				return -1;
			return (getBuffer()[super.getOffset()] & 0xf0) >>> 4;
		}

		/**
		 * @return the number of bytes of data in this header extension.
		 */
		public int getExtLength() {
			// "The 4-bit length is the number minus one of data bytes of this
			// header extension element following the one-byte header.
			// Therefore, the value zero in this field indicates that one byte
			// of data follows, and a value of 15 (the maximum) indicates
			// element data of 16 bytes."
			return (getBuffer()[super.getOffset()] & 0x0f) + 1;
		}
	}

	/**
	 * Implements an iterator over the RTP header extensions of a {@link RawPacket}.
	 */
	public class HeaderExtensions implements Iterator<HeaderExtension> {
		/**
		 * The offset of the next extension.
		 */
		private int nextOff;

		/**
		 * The remaining length of the extensions headers.
		 */
		private int remainingLen;

		/**
		 * The single {@link HeaderExtension} instance which will be updates with each
		 * iteration.
		 */
		private HeaderExtension headerExtension = new HeaderExtension();

		/**
		 * Resets the iterator to the beginning of the header extensions of the
		 * {@link RawPacket}.
		 */
		private void reset() {
			int len = getExtensionLength();
			if (len <= 0) {
				// No extensions.
				nextOff = -1;
				remainingLen = -1;
				return;
			}

			nextOff = getOffset() + FIXED_HEADER_SIZE + getCsrcCount(getBuffer(), getOffset(), getLength()) * 4
					+ EXT_HEADER_SIZE;
			remainingLen = len;
		}

		/**
		 * {@inheritDoc} Returns true if this {@link RawPacket} contains another header
		 * extension.
		 */
		@Override
		public boolean hasNext() {
			if (remainingLen <= 0 || nextOff < 0) {
				return false;
			}

			int len = getExtLength(getBuffer(), nextOff, remainingLen);
			if (len <= 0) {
				return false;
			}

			return true;
		}

		/**
		 * @return the length in bytes of an RTP header extension with an RFC5285
		 *         one-byte header. This is slightly different from
		 *         {@link HeaderExtension#getExtLength()} in that it includes the header
		 *         byte and checks the boundaries.
		 */
		private int getExtLength(byte[] buf, int off, int len) {
			if (len <= 2) {
				return -1;
			}

			// len=0 indicates 1 byte of data; add 1 more byte for the id/len
			// field itself.
			int extLen = (buf[off] & 0x0f) + 2;

			if (extLen > len) {
				return -1;
			}
			return extLen;
		}

		/**
		 * @return the next header extension of this {@link RawPacket}. Note that it
		 *         reuses the same object and only update its state.
		 */
		@Override
		public HeaderExtension next() {
			// Prepare this.headerExtension
			int extLen = getExtLength(getBuffer(), nextOff, remainingLen);
			if (extLen <= 0) {
				throw new IllegalStateException("Invalid extension length. Did hasNext() return true?");
			}
			headerExtension.setOffsetLength(nextOff, extLen);

			// Advance "next"
			nextOff += extLen;
			remainingLen -= extLen;

			return headerExtension;
		}
	}
}