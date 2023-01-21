/*
 * Derived from RawPacket and RTPUtils
 *
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

public class ByteBuffer {
	/**
	 * Byte array storing the content of this Packet Note that if this instance
	 * changes, then {@link #headerExtensions} MUST be reinitialized. It is best to
	 * use {@link #setBuffer(byte[])} instead of accessing this field directly.
	 */
	private byte[] buffer;

	/**
	 * Length of this packet's data
	 */
	private int length;

	/**
	 * Start offset of the packet data inside buffer. Usually this value would be 0.
	 * But in order to be compatible with RTPManager we store this info. (Not
	 * assuming the offset is always zero)
	 */
	private int offset;

	public ByteBuffer(byte[] buffer, int offset, int length) {
		this.buffer = buffer;
		this.offset = offset;
		this.length = length;
	}

	public ByteBuffer() {

	}

	/**
	 * Append a byte array to the end of the packet. This may change the data buffer
	 * of this packet.
	 *
	 * @param data byte array to append
	 * @param len  the number of bytes to append
	 */
	public void append(byte[] data, int len) {
		if (data == null || len == 0) {
			return;
		}

		// Ensure the internal buffer is long enough to accommodate data. (The
		// method grow will re-allocate the internal buffer if it's too short.)
		grow(len);
		// Append data.
		System.arraycopy(data, 0, buffer, length + offset, len);
		length += len;
	}

	/**
	 * Get buffer containing the content of this packet
	 *
	 * @return buffer containing the content of this packet
	 */
	public byte[] getBuffer() {
		return this.buffer;
	}

	/**
	 * Get the length of this packet's data
	 *
	 * @return length of this packet's data
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Get the start offset of this packet's data inside storing buffer
	 *
	 * @return start offset of this packet's data inside storing buffer
	 */
	public int getOffset() {
		return this.offset;
	}

	/**
	 * Grows the internal buffer of this {@code RawPacket}.
	 *
	 * This will change the data buffer of this packet but not the length of the
	 * valid data. Use this to grow the internal buffer to avoid buffer
	 * re-allocations when appending data.
	 *
	 * @param howMuch the number of bytes by which this {@code RawPacket} is to grow
	 */
	public void grow(int howMuch) {
		if (howMuch < 0)
			throw new IllegalArgumentException("howMuch");

		int newLength = length + howMuch;

		if (newLength > buffer.length - offset) {
			byte[] newBuffer = new byte[newLength];

			System.arraycopy(buffer, offset, newBuffer, 0, length);
			offset = 0;
			setBuffer(newBuffer);
		}
	}

	/**
	 * Read a byte from this packet at specified offset
	 *
	 * @param off start offset of the byte
	 * @return byte at offset
	 */
	public byte readByte(int off) {
		return buffer[offset + off];
	}

	/**
	 * Read a integer from this packet at specified offset
	 *
	 * @param off start offset of the integer to be read
	 * @return the integer to be read
	 */
	public int readInt(int off) {
		return readInt(buffer, offset + off);
	}

	/**
	 * Read a 32-bit unsigned integer from this packet at the specified offset.
	 *
	 * @param off start offset of the integer to be read.
	 * @return the integer to be read
	 */
	public long readUint32AsLong(int off) {
		return readUint32AsLong(buffer, offset + off);
	}

	/**
	 * Read a byte region from specified offset with specified length
	 *
	 * @param off start offset of the region to be read
	 * @param len length of the region to be read
	 * @return byte array of [offset, offset + length)
	 */
	public byte[] readRegion(int off, int len) {
		int startOffset = this.offset + off;
		if (off < 0 || len <= 0 || startOffset + len > this.buffer.length)
			return null;

		byte[] region = new byte[len];

		System.arraycopy(this.buffer, startOffset, region, 0, len);

		return region;
	}

	/**
	 * Read a byte region from specified offset with specified length in given
	 * buffer
	 *
	 * @param off     start offset of the region to be read
	 * @param len     length of the region to be read
	 * @param outBuff output buffer
	 */
	public void readRegionToBuff(int off, int len, byte[] outBuff) {
		int startOffset = this.offset + off;
		if (off < 0 || len <= 0 || startOffset + len > this.buffer.length)
			return;

		if (outBuff.length < len)
			return;

		System.arraycopy(this.buffer, startOffset, outBuff, 0, len);
	}

	/**
	 * Write a short to this packet at the specified offset.
	 *
	 */
	public void writeShort(int off, short val) {
		writeShort(buffer, offset + off, val);
	}

	/**
	 * Read an unsigned short at specified offset as a int
	 *
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public int readUint16AsInt(int off) {
		return readUint16AsInt(buffer, offset + off);
	}

	/**
	 * @param buffer the buffer to set
	 */
	public void setBuffer(byte[] buffer) {
		this.buffer = buffer;
	}

	/**
	 * @param length the length to set
	 */
	public void setLength(int length) {
		this.length = length;
	}

	/**
	 * @param offset the offset to set
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
	 * Shrink the buffer of this packet by specified length
	 *
	 * @param len length to shrink
	 */
	public void shrink(int len) {
		if (len <= 0)
			return;

		this.length -= len;
		if (this.length < 0)
			this.length = 0;
	}

	/**
	 * Write a byte to this packet at specified offset
	 *
	 * @param off start offset of the byte
	 * @param b   byte to write
	 */
	public void writeByte(int off, byte b) {
		buffer[offset + off] = b;
	}

	/**
	 * Set an integer at specified offset in network order.
	 *
	 * @param off  Offset into the buffer
	 * @param data The integer to store in the packet
	 */
	public void writeInt(int off, int data) {
		writeInt(buffer, offset + off, data);
	}

	/**
	 * Set an integer at specified offset in network order.
	 *
	 * @param off  Offset into the buffer
	 * @param data The integer to store in the packet
	 */
	public static int writeInt(byte[] buf, int off, int data) {
		if (buf == null || buf.length < off + 4) {
			return -1;
		}

		buf[off++] = (byte) (data >> 24);
		buf[off++] = (byte) (data >> 16);
		buf[off++] = (byte) (data >> 8);
		buf[off] = (byte) data;
		return 4;
	}

	/**
	 * Writes the least significant 24 bits from the given integer into the given
	 * byte array at the given offset.
	 * 
	 * @param buf  the buffer into which to write.
	 * @param off  the offset at which to write.
	 * @param data the integer to write.
	 * @return 3
	 */
	public static int writeUint24(byte[] buf, int off, int data) {
		if (buf == null || buf.length < off + 3) {
			return -1;
		}

		buf[off++] = (byte) (data >> 16);
		buf[off++] = (byte) (data >> 8);
		buf[off] = (byte) data;
		return 3;
	}

	/**
	 * Set an integer at specified offset in network order.
	 *
	 * @param off  Offset into the buffer
	 * @param data The integer to store in the packet
	 */
	public static int writeShort(byte[] buf, int off, short data) {
		buf[off++] = (byte) (data >> 8);
		buf[off] = (byte) data;
		return 2;
	}

	/**
	 * Read an integer from a buffer at a specified offset.
	 *
	 * @param buf the buffer.
	 * @param off start offset of the integer to be read.
	 */
	public static int readInt(byte[] buf, int off) {
		return ((buf[off++] & 0xFF) << 24) | ((buf[off++] & 0xFF) << 16) | ((buf[off++] & 0xFF) << 8)
				| (buf[off] & 0xFF);
	}

	/**
	 * Reads a 32-bit unsigned integer from the given buffer at the given offset and
	 * returns its {@link long} representation.
	 * 
	 * @param buf the buffer.
	 * @param off start offset of the integer to be read.
	 */
	public static long readUint32AsLong(byte[] buf, int off) {
		return readInt(buf, off) & 0xFFFF_FFFFL;
	}

	/**
	 * Read an unsigned short at a specified offset as an int.
	 *
	 * @param buf the buffer from which to read.
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public static int readUint16AsInt(byte[] buf, int off) {
		int b1 = (0xFF & (buf[off + 0]));
		int b2 = (0xFF & (buf[off + 1]));
		int val = b1 << 8 | b2;
		return val;
	}

	/**
	 * Read a signed short at a specified offset as an int.
	 *
	 * @param buf the buffer from which to read.
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public static int readInt16AsInt(byte[] buf, int off) {
		int ret = ((0xFF & (buf[off])) << 8) | (0xFF & (buf[off + 1]));
		if ((ret & 0x8000) != 0) {
			ret = ret | 0xFFFF_0000;
		}

		return ret;
	}

	/**
	 * Read an unsigned short at specified offset as a int
	 *
	 * @param buf
	 * @param off start offset of the unsigned short
	 * @return the int value of the unsigned short at offset
	 */
	public static int readUint24AsInt(byte[] buf, int off) {
		int b1 = (0xFF & (buf[off + 0]));
		int b2 = (0xFF & (buf[off + 1]));
		int b3 = (0xFF & (buf[off + 2]));
		return b1 << 16 | b2 << 8 | b3;
	}

	/**
	 * Returns the given integer masked to 16 bits
	 * 
	 * @param value the integer to mask
	 * @return the value, masked to only keep the lower 16 bits
	 */
	public static int as16Bits(int value) {
		return value & 0xFFFF;
	}

	/**
	 * Returns the given integer masked to 32 bits
	 * 
	 * @param value the integer to mask
	 * @return the value, masked to only keep the lower 32 bits
	 */
	public static long as32Bits(long value) {
		return value & 0xFFFF_FFFFL;
	}

	/**
	 * Sets the offset and the length of this {@link ByteArrayBuffer}
	 * 
	 * @param offset the offset to set.
	 * @param length the length to set.
	 */
	public void setOffsetLength(int offset, int length) {
		if (offset + length > buffer.length || length < 0 || offset < 0) {
			throw new IllegalArgumentException("length or offset");
		}
		this.offset = offset;
		this.length = length;
	}
}
