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

import java.math.BigInteger;

import jwebrtcpeer.srtp.RawPacket;

public class RTPStatistics {

	private int rtpPacketsReceived;
	private int cycles;

	private int firstSequenceNumber;
	private int lastSequenceNumber;

	private int lostPackets;

	private int expectedPacketsPrior;
	private int receivedPacketPrior;

	private int maxExtendedSequenceNumber;

	private long interarrivalJitter;
	private long lastRTPTimestamp, lastRTPArrivalTime;

	private int delaySinceLastSR;
	private long lastReceivedSRMilli;

	private int lastSR;

	public RTPStatistics() {
	}

	public void feedRTCPInfo(byte[] ntpTimestamp) {
		long timeNow = System.currentTimeMillis();

		double diffInSec = (timeNow - lastReceivedSRMilli) / 1000.0;
		delaySinceLastSR = (int) (diffInSec / (1 / 65536.0));

		// the middle 32 bits of the NTP timestamp
		byte[] lastSRBuf = new byte[4];
		System.arraycopy(ntpTimestamp, 2, lastSRBuf, 0, 4);
		lastSR = new BigInteger(lastSRBuf).intValue();
		lastReceivedSRMilli = timeNow;
	}

	public void feedRTPPacket(RawPacket packet) {
		if (rtpPacketsReceived != Integer.MAX_VALUE)
			rtpPacketsReceived++;

		int sequenceNumber = packet.getSequenceNumber();
		long rtpTimestamp = packet.getTimestamp();

		if (firstSequenceNumber == 0) {
			firstSequenceNumber = sequenceNumber;
			lastSequenceNumber = firstSequenceNumber;
			lastRTPTimestamp = rtpTimestamp;
			lastRTPArrivalTime = timeInTimestampUnits(90000);
			return;
		}

		if (sequenceNumber < lastSequenceNumber)
			if (cycles != Integer.MAX_VALUE)
				cycles++;

		// extended highest sequence number received
		maxExtendedSequenceNumber = (cycles * 65536) + sequenceNumber;

		int expectedPackets = maxExtendedSequenceNumber - firstSequenceNumber + 1;
		// cumulative number of packets lost
		lostPackets = expectedPackets - rtpPacketsReceived;

		// TODO grab the actual sample rate from the remote description
		long timeNow = timeInTimestampUnits(90000);
		long diff = (timeNow - rtpTimestamp) - (lastRTPArrivalTime - lastRTPTimestamp);

		interarrivalJitter = (long) (interarrivalJitter + (Math.abs(diff) - interarrivalJitter) / 16.0);

		lastSequenceNumber = sequenceNumber;
		lastRTPArrivalTime = timeNow;
		lastRTPTimestamp = rtpTimestamp;
	}

	private long timeInTimestampUnits(int sampleRate) {
		return (System.currentTimeMillis()) / 1000 * sampleRate;
	}

	/*
	 * This is supposed to be this part from the spec:
	 * 
	 * https://datatracker.ietf.org/doc/html/rfc3550#appendix-A.3
	 * 
	 */
	public byte calculateFractionLost() {
		int expectedPackets = maxExtendedSequenceNumber - firstSequenceNumber + 1;
		int expectedInterval = expectedPackets - expectedPacketsPrior;
		int receivedInterval = rtpPacketsReceived - receivedPacketPrior;
		int lostInterval = expectedInterval - receivedInterval;

		byte fraction;
		if (expectedInterval == 0 || lostInterval <= 0)
			fraction = 0;
		else
			fraction = (byte) ((lostInterval << 8) / expectedInterval);

		return fraction;
	}

	public int getLostPackets() {
		return lostPackets;
	}

	public int getMaxExtendedSequenceNumber() {
		return maxExtendedSequenceNumber;
	}

	public long getInterarrivalJitter() {
		return interarrivalJitter;
	}

	public int getDelaySinceLastSR() {
		return delaySinceLastSR;
	}

	public int getLastSR() {
		return lastSR;
	}
}
