/*   
 * Copyright 2022 pavlos4265
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
package jwebrtcpeer.udpmanager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.zip.CRC32;

import jwebrtcpeer.WebRTCUtils;

public class STUNHandler {

	public static void HandleBindingRequest(DatagramSocket socket, byte[] buffer, int length, String ufrag,
			String icepwd, InetAddress address, int port)
			throws IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		DataInputStream din = new DataInputStream(new ByteArrayInputStream(buffer, 0, length));

		int msgType = din.readShort();
		if (WebRTCUtils.DEBUG)
			System.out.println("STUN packet type: 0x" + Integer.toHexString(msgType));

		// if it's not a binding request
		if (msgType != 0x0001)
			return;

		int msgLength = din.readShort();
		if (WebRTCUtils.DEBUG)
			System.out.println("STUN packet length: " + msgLength);

		byte[] cookie = new byte[4];
		din.read(cookie);

		byte[] transactionId = new byte[12];
		din.read(transactionId);

		while (true) {
			try {
				boolean process = STUNHandler.ProcessAttribute(din, ufrag);
				if (!process)
					return;
			} catch (EOFException e) {
				break;
			}
		}

		byte[] response = GenerateResponse(cookie, transactionId, icepwd, address, port);
		DatagramPacket packet = new DatagramPacket(response, response.length);
		socket.send(packet);

		if (WebRTCUtils.DEBUG)
			System.out.println("STUN binding response sent");
	}

	private static boolean ProcessAttribute(DataInputStream din, String ufrag) throws IOException {
		int type = din.readUnsignedShort();

		int length = din.readShort();

		if (length == 0)
			return true;

		int valueLenBits = length * 8 <= 32 ? 32 : ((int) (Math.ceil((length * 8) / 32.0)) * 32);
		byte[] value = new byte[valueLenBits / 8];
		din.read(value, 0, value.length); // read value

		if (GetSTUNType(type) == STUNType.USERNAME) { // USERNAME attribute
			String user = new String(value).split(":")[0];

			if (!user.equals(ufrag)) {
				if (WebRTCUtils.DEBUG)
					System.out.println("STUN attribute USERNAME doesn't match ufrag.");
				return false;
			}
		}

		return true;
	}

	private static byte[] GenerateResponse(byte[] cookie, byte[] transactionId, String icepwd, InetAddress address,
			int port) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream out = new DataOutputStream(baos);

		out.writeShort(0x0101); // stun message type
		out.writeShort(0x0038); // length (56 bytes)
		out.write(cookie);
		out.write(transactionId);

		// xor-mapped address
		out.writeShort(0x0020); // xor mapped address type
		out.writeShort(0x0008); // length (8 bytes)

		out.writeByte(0x00); // 0
		out.writeByte(0x01); // family: ipv4

		byte[] portBuf = new byte[2];
		int sPort = Short.toUnsignedInt((short) port);

		portBuf[1] = (byte) (sPort & 0x000000ff);
		sPort >>= 8;
		portBuf[0] = (byte) (sPort & 0x000000ff);

		out.write((portBuf[0] & 0xff) ^ (cookie[0] & 0xff));
		out.write((portBuf[1] & 0xff) ^ (cookie[1] & 0xff));

		byte[] addrBuf = address.getAddress();
		out.write((addrBuf[0] & 0xff) ^ (cookie[0] & 0xff));
		out.write((addrBuf[1] & 0xff) ^ (cookie[1] & 0xff));
		out.write((addrBuf[2] & 0xff) ^ (cookie[2] & 0xff));
		out.write((addrBuf[3] & 0xff) ^ (cookie[3] & 0xff));

		// ice-controlled
		out.writeShort(0x8029);
		out.writeShort(0x0008);
		out.writeInt(100); // random
		out.writeInt(200); // random

		// message-integrity
		byte[] temp = baos.toByteArray();
		temp[3] = 0x30; // subtract the fingerprint length from the total length, shouldn't be included
						// in message integrity
		byte[] hashedData = WebRTCUtils.CalculateRFC2104HMAC(temp, icepwd);
		out.writeShort(0x0008); // message integrity type
		out.writeShort(0x0014); // length (20 bytes - 160 bits)

		out.write(hashedData);

		// fingerprint
		temp = baos.toByteArray();
		out.writeShort(0x8028); // fingerprint type
		out.writeShort(0x0004); // length (4 bytes - 32 bits)

		CRC32 c = new CRC32();
		c.update(temp);
		int crc = (int) c.getValue();
		crc ^= 0x5354554e;

		out.writeInt(crc);

		byte[] fBuf = baos.toByteArray();
		return fBuf;
	}

	private static STUNType GetSTUNType(int type) {
		switch (type) {
		case 0x0001:
			return STUNType.MAPPED_ADDRESS;
		case 0x0006:
			return STUNType.USERNAME;
		case 0x0008:
			return STUNType.MESSAGE_INTEGRITY;
		case 0x0009:
			return STUNType.ERROR_CODE;
		case 0x0020:
			return STUNType.XOR_MAPPED_ADDRESS;
		case 0x8028:
			return STUNType.FINGERPRINT;
		default:
			return STUNType.UNKNOWN;
		}
	}

	private enum STUNType {
		MAPPED_ADDRESS, USERNAME, MESSAGE_INTEGRITY, ERROR_CODE, XOR_MAPPED_ADDRESS, FINGERPRINT, UNKNOWN
	}
}
