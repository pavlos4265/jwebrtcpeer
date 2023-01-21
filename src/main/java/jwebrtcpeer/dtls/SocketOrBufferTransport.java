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
package jwebrtcpeer.dtls;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsFatalAlert;

public class SocketOrBufferTransport implements DatagramTransport {
	protected final static int MIN_IP_OVERHEAD = 20;
	protected final static int MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64;
	protected final static int UDP_OVERHEAD = 8;

	protected final DatagramSocket socket;
	protected final int receiveLimit, sendLimit;

	private byte[] data = null;
	private int dataLength;

	public SocketOrBufferTransport(DatagramSocket socket, int mtu) {
		this.socket = socket;
		this.receiveLimit = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD;
		this.sendLimit = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD;
	}

	public int getReceiveLimit() {
		return receiveLimit;
	}

	public int getSendLimit() {
		return sendLimit;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public void setDataLength(int dataLength) {
		this.dataLength = dataLength;
	}

	public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException {
		if (data == null) {
			DatagramPacket packet = new DatagramPacket(buf, off, len);
			socket.receive(packet);

			return packet.getLength();
		}

		// use the already read bytes instead of trying to receive new
		int minLength = (dataLength < len) ? dataLength : len;
		buf = data;
		data = null;
		return minLength;
	}

	public void send(byte[] buf, int off, int len) throws IOException {
		if (len > getSendLimit()) {
			/*
			 * RFC 4347 4.1.1. "If the application attempts to send a record larger than the
			 * MTU, the DTLS implementation SHOULD generate an error, thus avoiding sending
			 * a packet which will be fragmented."
			 */
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		DatagramPacket packet = new DatagramPacket(buf, off, len);
		socket.send(packet);
	}

	public void close() throws IOException {
		socket.close();
	}
}
