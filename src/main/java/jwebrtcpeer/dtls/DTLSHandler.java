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
import java.net.DatagramSocket;

import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;

import jwebrtcpeer.WebRTCUtils;

public class DTLSHandler {
	private String remoteFingerprint;

	private DTLSTransport dtlsTransport;
	private SocketOrBufferTransport dataTransport;
	private DTLSServer server;
	private DTLSListener dtlsListener;

	public DTLSHandler(DatagramSocket socket, String remoteFingerprint, DTLSListener dtlsListener) {
		this.remoteFingerprint = remoteFingerprint;
		this.dataTransport = new SocketOrBufferTransport(socket, 1500);
		this.dtlsListener = dtlsListener;
	}

	public void handlePacket(byte[] buffer, int length) throws IOException {
		if (dtlsTransport == null) {
			dataTransport.setData(buffer);
			dataTransport.setDataLength(length);

			server = new DTLSServer(remoteFingerprint, dtlsListener);
			DTLSServerProtocol serverProtocol = new DTLSServerProtocol();
			dtlsTransport = serverProtocol.accept(server, dataTransport, null);
			if (WebRTCUtils.DEBUG)
				System.out.println("DTLS handshake complete");
			return;
		}

		dataTransport.setData(buffer);
		dataTransport.setDataLength(length);

		byte[] data = new byte[2048];
		int receivedLength = dtlsTransport.receive(data, 0, data.length, 1);

		if (WebRTCUtils.DEBUG)
			System.out.println("DTLS data received " + receivedLength + " bytes");

		// TODO:: maybe do something with the incoming data
	}

	public DTLSServer getDTLSServer() {
		return server;
	}
}
