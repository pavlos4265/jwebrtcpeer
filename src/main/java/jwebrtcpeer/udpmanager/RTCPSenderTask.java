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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Map;
import java.util.TimerTask;

import jwebrtcpeer.WebRTCUtils;
import jwebrtcpeer.srtp.RawPacket;
import jwebrtcpeer.srtp.SRTPHandler;

public class RTCPSenderTask extends TimerTask {

	private long ssrcSender;
	private Map<Long, RTPStatistics> rtpStatistics;
	private DatagramSocket socket;
	private SRTPHandler srtpHandler;

	public RTCPSenderTask(long ssrcSender, Map<Long, RTPStatistics> rtpStatistics, DatagramSocket socket,
			SRTPHandler srtpHandler) {
		this.ssrcSender = ssrcSender;
		this.rtpStatistics = rtpStatistics;
		this.socket = socket;
		this.srtpHandler = srtpHandler;
	}

	@Override
	public void run() {
		try {
			generateRTCPReceiverReport();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void generateRTCPReceiverReport() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream output = new DataOutputStream(baos);

		byte firstByte = (byte) rtpStatistics.size();
		// first byte is version, padding and number of report blocks
		firstByte = (byte) (firstByte | 0b10000000);
		output.write(firstByte);

		// receiver report
		output.write(201);

		// the length in 32-bit words - 1.
		// 2 words for the header, and 6 for each block
		short length = (short) (2 + 6 * rtpStatistics.size() - 1);
		output.writeShort(length);

		output.writeInt((int) ssrcSender);

		for (long ssrc : rtpStatistics.keySet()) {
			output.writeInt((int) ssrc);
			RTPStatistics rtpStats = rtpStatistics.get(ssrc);

			int fractionAndLost = ((int) rtpStats.calculateFractionLost() << 24) | rtpStats.getLostPackets();
			output.writeInt(fractionAndLost);
			output.writeInt(rtpStats.getMaxExtendedSequenceNumber());
			output.writeInt((int) rtpStats.getInterarrivalJitter());
			output.writeInt(rtpStats.getLastSR());
			output.writeInt(rtpStats.getDelaySinceLastSR());
			System.out.println("ssrc: " + ssrc + " jitter: " + rtpStats.getInterarrivalJitter() / 90000.0 + "s");
		}

		byte[] buf = baos.toByteArray();

		if (srtpHandler == null)
			return;

		RawPacket encryptedPacket = srtpHandler.encryptSRTCPPacket(buf, buf.length);
		if (encryptedPacket != null) {
			DatagramPacket packet = new DatagramPacket(encryptedPacket.getBuffer(), encryptedPacket.getLength());
			socket.send(packet);
			if (WebRTCUtils.DEBUG)
				System.out.println("RTCP receiver report generated and sent");
		}
	}
}