/*
 * Copyright @ 2019 - present 8x8, Inc
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
 * */

package jwebrtcpeer.srtp;

import java.security.*;
import javax.crypto.*;

import jwebrtcpeer.srtp.crypto.*;

import java.util.*;

/**
 * SrtpKdf performs the SRTP key derivation function, as specified in section
 * 4.3 of RFC 3711.
 */
class SRTPKdf {
	/** The SRTP KDF label value for RTP encryption. */
	static final byte LABEL_RTP_ENCRYPTION = 0x00;

	/** The SRTP KDF label value for RTP message authentication. */
	static final byte LABEL_RTP_MSG_AUTH = 0x01;

	/** The SRTP KDF label value for RTP message salting. */
	static final byte LABEL_RTP_SALT = 0x02;

	/** The SRTP KDF label value for RTCP encryption. */
	static final byte LABEL_RTCP_ENCRYPTION = 0x03;

	/** The SRTP KDF label value for RTCP message authentication. */
	static final byte LABEL_RTCP_MSG_AUTH = 0x04;

	/** The SRTP KDF label value for RTCP message salting. */
	static final byte LABEL_RTCP_SALT = 0x05;

	/**
	 * implements the counter cipher mode for RTP key derivation according to RFC
	 * 3711
	 */
	private final SRTPCipherCtr cipherCtr;

	/**
	 * Master salting key
	 */
	private final byte[] masterSalt;

	/**
	 * Temp store.
	 */
	private final byte[] ivStore = new byte[16];

	/**
	 * Construct an SRTP Key Derivation Function object.
	 *
	 * @param masterK The master key from which to derive keys.
	 * @param masterS The master salt from which to derive keys.
	 * @param policy  The SRTP policy to use for key derivation.
	 */
	SRTPKdf(byte[] masterK, byte[] masterS, SRTPPolicy policy) throws GeneralSecurityException {

		switch (policy.getEncType()) {
		case SRTPPolicy.AESF8_ENCRYPTION:
		case SRTPPolicy.AESCM_ENCRYPTION:
		case SRTPPolicy.AESGCM_ENCRYPTION:
			cipherCtr = new SRTPCipherCtr(Aes.createCipher("AES/CTR/NoPadding"));
			break;

		case SRTPPolicy.TWOFISHF8_ENCRYPTION:
		case SRTPPolicy.TWOFISH_ENCRYPTION:
			cipherCtr = new SRTPCipherCtr(Cipher.getInstance("Twofish/CTR/NoPadding"));
			break;

		case SRTPPolicy.NULL_ENCRYPTION:
		default:
			cipherCtr = null;
			break;
		}

		if (cipherCtr != null) {
			cipherCtr.init(masterK, null);
		}

		int saltKeyLength = policy.getSaltKeyLength();
		masterSalt = new byte[saltKeyLength];
		if (saltKeyLength != 0) {
			System.arraycopy(masterS, 0, masterSalt, 0, saltKeyLength);
		}
	}

	/**
	 * Derive a session key.
	 *
	 * @param sessKey A buffer into which the derived session key will be placed.
	 *                This should be allocated to be the desired key length.
	 * @param label   The key derivation label.
	 */
	void deriveSessionKey(byte[] sessKey, byte label) throws GeneralSecurityException {
		if (sessKey == null || sessKey.length == 0) {
			return;
		}

		assert (masterSalt.length < ivStore.length);
		System.arraycopy(masterSalt, 0, ivStore, 0, masterSalt.length);

		ivStore[7] ^= label;
		for (int i = masterSalt.length; i < ivStore.length; i++) {
			ivStore[i] = 0;
			ivStore[i] = 0;
		}

		Arrays.fill(sessKey, (byte) 0);
		cipherCtr.setIV(ivStore, Cipher.ENCRYPT_MODE);
		cipherCtr.process(sessKey, 0, sessKey.length);
	}
}
