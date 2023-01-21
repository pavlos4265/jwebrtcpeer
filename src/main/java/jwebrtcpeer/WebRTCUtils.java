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
package jwebrtcpeer;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Hashtable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.tls.CertificateEntry;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class WebRTCUtils {

	public static final String CERT_FILE = "x509-server-rsa-sign.pem";
	public static final String CERT_KEY_FILE = "x509-server-key-rsa-sign.pem";

	public static final boolean DEBUG = true;

	public static Certificate LoadBcCertificateResource(String resource) throws IOException {
		PemObject pem = LoadPemResource(resource);
		if (pem.getType().endsWith("CERTIFICATE"))
			return Certificate.getInstance(pem.getContent());

		throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
	}

	public static TlsCertificate LoadCertificateResource(TlsCrypto crypto, String resource) throws IOException {
		PemObject pem = LoadPemResource(resource);
		if (pem.getType().endsWith("CERTIFICATE"))
			return crypto.createCertificate(pem.getContent());

		throw new IllegalArgumentException("'resource' doesn't specify a valid certificate");
	}

	public static AsymmetricKeyParameter LoadBcPrivateKeyResource(String resource) throws IOException {
		PemObject pem = LoadPemResource(resource);
		if (pem.getType().equals("PRIVATE KEY"))
			return PrivateKeyFactory.createKey(pem.getContent());

		if (pem.getType().equals("ENCRYPTED PRIVATE KEY"))
			throw new UnsupportedOperationException("Encrypted PKCS#8 keys not supported");

		if (pem.getType().equals("RSA PRIVATE KEY")) {
			RSAPrivateKey rsa = RSAPrivateKey.getInstance(pem.getContent());
			return new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(), rsa.getPrivateExponent(),
					rsa.getPrime1(), rsa.getPrime2(), rsa.getExponent1(), rsa.getExponent2(), rsa.getCoefficient());
		}

		if (pem.getType().equals("EC PRIVATE KEY")) {
			ECPrivateKey pKey = ECPrivateKey.getInstance(pem.getContent());
			AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
					pKey.getParameters());
			PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);
			return PrivateKeyFactory.createKey(privInfo);
		}

		throw new IllegalArgumentException("'resource' doesn't specify a valid private key");
	}

	@SuppressWarnings("rawtypes")
	public static org.bouncycastle.tls.Certificate LoadCertificateChain(ProtocolVersion protocolVersion,
			TlsCrypto crypto, String[] resources) throws IOException {
		if (TlsUtils.isTLSv13(protocolVersion)) {
			CertificateEntry[] certificateEntryList = new CertificateEntry[resources.length];
			for (int i = 0; i < resources.length; ++i) {
				TlsCertificate certificate = LoadCertificateResource(crypto, resources[i]);

				// TODO[tls13] Add possibility of specifying e.g. CertificateStatus
				Hashtable extensions = null;

				certificateEntryList[i] = new CertificateEntry(certificate, extensions);
			}

			// TODO[tls13] Support for non-empty request context
			byte[] certificateRequestContext = TlsUtils.EMPTY_BYTES;

			return new org.bouncycastle.tls.Certificate(certificateRequestContext, certificateEntryList);
		}

		TlsCertificate[] chain = new TlsCertificate[resources.length];
		for (int i = 0; i < resources.length; ++i) {
			chain[i] = LoadCertificateResource(crypto, resources[i]);
		}

		return new org.bouncycastle.tls.Certificate(chain);
	}

	public static PemObject LoadPemResource(String resource) throws IOException {
		InputStream s = new FileInputStream(resource);
		PemReader p = new PemReader(new InputStreamReader(s));
		PemObject o = p.readPemObject();
		p.close();
		return o;
	}

	public static String Fingerprint(String resource) throws IOException {
		Certificate certificate = LoadBcCertificateResource(resource);
		return Fingerprint(certificate);
	}

	public static String Fingerprint(Certificate c) throws IOException {
		byte[] der = c.getEncoded();
		byte[] sha256 = SHA256DigestOf(der);
		byte[] hexBytes = Hex.encode(sha256);
		String hex = new String(hexBytes, "ASCII").toUpperCase();

		StringBuffer fp = new StringBuffer();
		int i = 0;
		fp.append(hex.substring(i, i + 2));
		while ((i += 2) < hex.length()) {
			fp.append(':');
			fp.append(hex.substring(i, i + 2));
		}
		return fp.toString();
	}

	private static byte[] SHA256DigestOf(byte[] input) {
		SHA256Digest d = new SHA256Digest();
		d.update(input, 0, input.length);
		byte[] result = new byte[d.getDigestSize()];
		d.doFinal(result, 0);
		return result;
	}

	public static byte[] CalculateRFC2104HMAC(byte[] data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		String algorithm = "HmacSHA1";
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), algorithm);
		Mac mac = Mac.getInstance(algorithm);
		mac.init(signingKey);
		return mac.doFinal(data);
	}
}
