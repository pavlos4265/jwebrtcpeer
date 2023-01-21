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

import org.bouncycastle.tls.SRTPProtectionProfile;

public class SRTPPolicies {

	private SRTPPolicy srtpPolicy, srtcpPolicy;

	public SRTPPolicies(int profile) {
		switch (profile) {
		case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
			srtpPolicy = generateSrtpPolicy(SRTPPolicy.AESCM_ENCRYPTION, 16, SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, 10,
					14);
			srtcpPolicy = generateSrtpPolicy(SRTPPolicy.AESCM_ENCRYPTION, 16, SRTPPolicy.HMACSHA1_AUTHENTICATION, 20,
					10, 14);
			break;
		case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
			srtpPolicy = generateSrtpPolicy(SRTPPolicy.AESCM_ENCRYPTION, 16, SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, 4,
					14);
			srtcpPolicy = generateSrtpPolicy(SRTPPolicy.AESCM_ENCRYPTION, 16, SRTPPolicy.HMACSHA1_AUTHENTICATION, 20,
					10, 14);
			break;
		default:
			System.out.println("Unknown SRTP profile");
		}
	}

	private SRTPPolicy generateSrtpPolicy(int encType, int encKeyLength, int authType, int authKeyLength,
			int authTagLength, int saltKeyLength) {
		return new SRTPPolicy(encType, encKeyLength, authType, authKeyLength, authTagLength, saltKeyLength);
	}

	public SRTPPolicy getSRTPPolicy() {
		return srtpPolicy;
	}

	public SRTPPolicy getSRTCPPolicy() {
		return srtcpPolicy;
	}

}
