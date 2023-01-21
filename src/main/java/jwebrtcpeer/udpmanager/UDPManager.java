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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;

import jwebrtcpeer.PeerConnectionListener;
import jwebrtcpeer.WebRTCUtils;
import jwebrtcpeer.dtls.DTLSHandler;
import jwebrtcpeer.dtls.DTLSListener;
import jwebrtcpeer.dtls.DTLSServer;
import jwebrtcpeer.srtp.RawPacket;
import jwebrtcpeer.srtp.SRTPHandler;

public class UDPManager extends Thread {

	private String ufrag, icepwd, remoteFingerprint;
	private int port;

	private DTLSHandler dtlsHandler;
	private SRTPHandler srtpHandlerClient, srtpHandlerServer;

	private DatagramSocket socket;

	private boolean disableReceiverReports;

	private PeerConnectionListener listener;

	// a rtpstatistics instance for each ssrc
	private Map<Long, RTPStatistics> rtpStatistics;

	private Timer rtcpSenderTimer;

	public UDPManager(String ufrag, String icepwd, String remoteFingerprint, int port, boolean disableReceiverReports,
			PeerConnectionListener listener) {
		this.ufrag = ufrag;
		this.icepwd = icepwd;
		this.remoteFingerprint = remoteFingerprint;
		this.port = port;
		this.disableReceiverReports = disableReceiverReports;
		this.listener = listener;

		rtpStatistics = new HashMap<>();
	}

	@Override
	public void run() {
		try {
			if (WebRTCUtils.DEBUG)
				System.out.println("UDPManager started at port " + port);

			socket = new DatagramSocket(port);

			boolean listening = true;
			while (listening) {
				byte[] buffer = new byte[2048];
				DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

				socket.receive(packet);

				if (!socket.isConnected()) {
					socket.connect(packet.getAddress(), packet.getPort());
					socket.setSoTimeout(8000);
				}

				handlePacket(buffer, packet.getLength(), packet.getAddress(), packet.getPort());

				Thread.sleep(1);
			}

			socket.close();
		} catch (IOException | InvalidKeyException | SignatureException | NoSuchAlgorithmException
				| InterruptedException e) {
			if (e instanceof SocketTimeoutException) {
				if (WebRTCUtils.DEBUG)
					System.out.println("UDPManager at port " + port + " has expired");

			} else
				e.printStackTrace();

			if (rtcpSenderTimer != null)
				rtcpSenderTimer.cancel();
			socket.close();
		}
	}

	private void handlePacket(byte[] buffer, int length, InetAddress srcAddress, int srcPort)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, IOException {
		int packetType = buffer[0] & 0xFF;

		if (WebRTCUtils.DEBUG)
			System.out.println("UDPManager received packet: " + UDPManager.GetPacketType(packetType));

		switch (UDPManager.GetPacketType(packetType)) {
		case STUN:
			STUNHandler.HandleBindingRequest(socket, buffer, length, ufrag, icepwd, srcAddress, srcPort);
			break;
		case DTLS:
			handleDTLS(buffer, length);
			break;
		case SRTP_SRTCP:
			handleSRTP(buffer, length);
			break;
		default:
			break;
		}
	}

	private void handleDTLS(byte[] buffer, int length) throws IOException {
		if (dtlsHandler == null) {
			DTLSListener dtlsListener = () -> generateSRTPHandlers();

			dtlsHandler = new DTLSHandler(socket, remoteFingerprint, dtlsListener);
		}

		dtlsHandler.handlePacket(buffer, length);
	}

	private void handleSRTP(byte[] buffer, int length) {
		if (srtpHandlerClient == null)
			return;

		RawPacket decryptedPacket = srtpHandlerClient.decryptSRTPPacket(buffer, length);
		if (decryptedPacket != null) {
			listener.onRTPPacket(decryptedPacket);

			long ssrc = decryptedPacket.getSSRCAsLong();
			if (rtpStatistics.get(ssrc) == null)
				rtpStatistics.put(ssrc, new RTPStatistics());

			rtpStatistics.get(ssrc).feedRTPPacket(decryptedPacket);
		}

		decryptedPacket = srtpHandlerClient.decryptSRTCPPacket(buffer, length);
		if (decryptedPacket != null) {
			listener.onRTCPPacket(decryptedPacket);

			int packetType = (decryptedPacket.readByte(1) & 0xff);
			// it's a sender report
			if (packetType == 200)
				analyzeSenderReport(decryptedPacket);
		}
	}

	public void sendMedia(byte[] data, int length, boolean isrtcp) throws IOException, Exception {
		if (dtlsHandler == null || dtlsHandler.getDTLSServer() == null)
			throw new IOException("There is no active dtls connection.");

		if (srtpHandlerServer == null)
			throw new Exception("The SRTP handler is not initialised.");

		RawPacket encryptedPacket;
		if (!isrtcp)
			encryptedPacket = srtpHandlerServer.encryptSRTPPacket(data, length);
		else
			encryptedPacket = srtpHandlerServer.encryptSRTCPPacket(data, length);

		if (encryptedPacket != null) {
			DatagramPacket packet = new DatagramPacket(encryptedPacket.getBuffer(), encryptedPacket.getLength());
			socket.send(packet);

			if (WebRTCUtils.DEBUG)
				System.out.println("RTP ssrc:" + encryptedPacket.getSSRCAsLong() + " isrtcp:" + isrtcp
						+ " sent to receiver " + socket.getInetAddress());
		} else
			throw new Exception("Failed to encrypt the rtp/rtcp packet.");
	}

	private void analyzeSenderReport(RawPacket packet) {
		long ssrcSender = packet.getSSRCAsLong();
		byte[] ntpTimestamp = packet.readRegion(8, 8);

		for (long ssrc : rtpStatistics.keySet()) {
			rtpStatistics.get(ssrc).feedRTCPInfo(ntpTimestamp);
		}

		// start a timer that sends rtcp receiver reports every x milliseconds
		if (!disableReceiverReports && rtcpSenderTimer == null && srtpHandlerServer != null) {
			rtcpSenderTimer = new Timer();
			// TODO: dynamic period instead of fixed
			rtcpSenderTimer.schedule(new RTCPSenderTask(ssrcSender, rtpStatistics, socket, srtpHandlerServer), 2000,
					5000);
		}
	}

	private void generateSRTPHandlers() {
		DTLSServer dtlsServer = dtlsHandler.getDTLSServer();
		srtpHandlerClient = new SRTPHandler(false, dtlsServer.getSRTPMasterClientKey(),
				dtlsServer.getSRTPMasterClientSalt(), dtlsServer.getSRTPPolicy(), dtlsServer.getSRTCPPolicy());
		srtpHandlerServer = new SRTPHandler(true, dtlsServer.getSRTPMasterServerKey(),
				dtlsServer.getSRTPMasterServerSalt(), dtlsServer.getSRTPPolicy(), dtlsServer.getSRTCPPolicy());
	}

	public boolean isConnected() {
		return (socket != null && socket.isConnected());
	}

	private static PacketType GetPacketType(int type) {
		if (type >= 0 && type <= 3)
			return PacketType.STUN;

		if (type >= 16 && type <= 19)
			return PacketType.ZRTP;

		if (type >= 20 && type <= 63)
			return PacketType.DTLS;

		if (type >= 64 && type <= 79)
			return PacketType.TURN;

		if (type >= 128 && type <= 191)
			return PacketType.SRTP_SRTCP;

		return PacketType.UNKNOWN;
	}
}
