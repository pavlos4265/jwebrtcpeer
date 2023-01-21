/*
 * Copyright @ 2015 - present 8x8, Inc
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
package jwebrtcpeer.srtp.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import jwebrtcpeer.srtp.crypto.Aes.SunPKCS11CipherFactory;

/**
 * Implements a factory for an HMAC-SHA1 {@link Mac}.
 *
 * @author Lyubomir Marinov
 */
public class HmacSha1 {
	private static List<Provider> providers;

	private static synchronized List<Provider> getProviders() {
		if (providers == null) {
			providers = new ArrayList<>();

			providers.add(Security.getProvider("SunJCE"));
			try {
				Provider pkcs11Provider = SunPKCS11CipherFactory.getProvider();
				if (pkcs11Provider != null) {
					providers.add(pkcs11Provider);
				}
			} catch (Exception e) {
				// logger.debug(() -> "PKCS#11 provider not available for HMAC: " +
				// e.getMessage());
			}
			providers.add(new BouncyCastleProvider());
		}

		return providers;
	}

	/**
	 * Initializes a new {@link Mac} instance which implements a keyed-hash message
	 * authentication code (HMAC) with SHA-1.
	 *
	 * @param parentLogger the logging context
	 * @return a new {@link Mac} instance which implements a keyed-hash message
	 *         authentication code (HMAC) with SHA-1
	 */
	public static Mac createMac() {
		// Try providers in order
		for (Provider p : getProviders()) {
			try {
				Mac mac = Mac.getInstance("HmacSHA1", p);

				return mac;
			} catch (NoSuchAlgorithmException e) {
				// continue
			}
		}

		throw new RuntimeException("No HmacSHA1 provider found");
	}
}
