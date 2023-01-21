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
package jwebrtcpeer.srtp;

public class SRTPHandler {

	private SRTPTransformEngine srtpTranformEngine;

	public SRTPHandler(boolean sender, byte[] masterKey, byte[] masterSalt, SRTPPolicy srtpPolicy,
			SRTPPolicy srtcpPolicy) {
		this.srtpTranformEngine = new SRTPTransformEngine(sender, masterKey, masterSalt, srtpPolicy, srtcpPolicy);
	}

	public RawPacket decryptSRTPPacket(byte[] buffer, int length) {
		RawPacket decryptedPacket;

		RawPacket packet = new RawPacket(buffer, 0, length);
		SRTPTransformer srtpTransformer = srtpTranformEngine.getSrtpTransformer();
		if ((decryptedPacket = srtpTransformer.reverseTransform(packet)) != null) {
			return decryptedPacket;
		}

		return null;
	}

	public RawPacket decryptSRTCPPacket(byte[] buffer, int length) {
		RawPacket decryptedPacket;

		RawPacket packet = new RawPacket(buffer, 0, length);
		SRTCPTransformer srtcpTransformer = srtpTranformEngine.getSrtcpTransformer();
		if ((decryptedPacket = srtcpTransformer.reverseTransform(packet)) != null) {
			return decryptedPacket;
		}

		return null;
	}

	public RawPacket encryptSRTPPacket(byte[] buffer, int length) {
		RawPacket encryptedPacket;

		RawPacket packet = new RawPacket(buffer, 0, length);
		SRTPTransformer srtpTransformer = srtpTranformEngine.getSrtpTransformer();
		if ((encryptedPacket = srtpTransformer.transform(packet)) != null) {
			return encryptedPacket;
		}

		return null;
	}

	public RawPacket encryptSRTCPPacket(byte[] buffer, int length) {
		RawPacket encryptedPacket;

		RawPacket packet = new RawPacket(buffer, 0, length);
		SRTCPTransformer srtcpTransformer = srtpTranformEngine.getSrtcpTransformer();
		if ((encryptedPacket = srtcpTransformer.transform(packet)) != null) {
			return encryptedPacket;
		}

		return null;
	}
}
