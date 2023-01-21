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
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.ExporterLabel;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SRTPProtectionProfile;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsSRTPUtils;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.UseSRTPData;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import jwebrtcpeer.WebRTCUtils;
import jwebrtcpeer.srtp.SRTPPolicies;
import jwebrtcpeer.srtp.SRTPPolicy;

public class DTLSServer extends DefaultTlsServer {
	private UseSRTPData useSRTPData;

	private byte[] srtpMasterClientKey;
	private byte[] srtpMasterServerKey;
	private byte[] srtpMasterClientSalt;
	private byte[] srtpMasterServerSalt;

	private SRTPPolicy srtpPolicy;
	private SRTPPolicy srtcpPolicy;

	private String remoteFingerprint;

	private DTLSListener dtlsListener;

	public DTLSServer(String remoteFingerprint, DTLSListener dtlsListener) {
		super(new BcTlsCrypto(new SecureRandom()));
		this.remoteFingerprint = remoteFingerprint;
		this.dtlsListener = dtlsListener;
	}

	public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
		if (WebRTCUtils.DEBUG) {
			PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			out.println("DTLS server raised alert: " + AlertLevel.getText(alertLevel) + ", "
					+ AlertDescription.getText(alertDescription));
			if (message != null)
				out.println("> " + message);

			if (cause != null)
				cause.printStackTrace(out);
		}
	}

	public void notifyAlertReceived(short alertLevel, short alertDescription) {
		if (WebRTCUtils.DEBUG) {
			PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
			out.println("DTLS server received alert: " + AlertLevel.getText(alertLevel) + ", "
					+ AlertDescription.getText(alertDescription));
			out.close();
		}
	}

	public ProtocolVersion getServerVersion() throws IOException {
		ProtocolVersion serverVersion = super.getServerVersion();

		if (WebRTCUtils.DEBUG)
			System.out.println("DTLS server negotiated " + serverVersion);

		return serverVersion;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Hashtable<Integer, byte[]> getServerExtensions() throws IOException {
		Hashtable<Integer, byte[]> serverExtensions = (Hashtable<Integer, byte[]>) super.getServerExtensions();
		if (TlsSRTPUtils.getUseSRTPExtension(serverExtensions) == null) {
			if (serverExtensions == null) {
				serverExtensions = new Hashtable<Integer, byte[]>();
			}

			TlsSRTPUtils.addUseSRTPExtension(serverExtensions, useSRTPData);
		}

		return serverExtensions;
	}

	public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException {
		TlsCertificate[] chain = clientCertificate.getCertificateList();

		if (WebRTCUtils.DEBUG)
			System.out.println("DTLS server received client certificate chain of length " + chain.length);

		for (int i = 0; i != chain.length; i++) {
			org.bouncycastle.asn1.x509.Certificate entry = org.bouncycastle.asn1.x509.Certificate
					.getInstance(chain[i].getEncoded());

			if (WebRTCUtils.Fingerprint(entry).equalsIgnoreCase(remoteFingerprint))
				return;
		}

		throw new TlsFatalAlert(AlertDescription.certificate_unknown);
	}

	@SuppressWarnings("rawtypes")
	public CertificateRequest getCertificateRequest() throws IOException {
		short[] certificateTypes = new short[] { ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign,
				ClientCertificateType.ecdsa_sign };

		Vector serverSigAlgs = null;
		if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(context.getServerVersion()))
			serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);

		return new CertificateRequest(certificateTypes, serverSigAlgs, null);
	}

	public void notifyHandshakeComplete() throws IOException {
		super.notifyHandshakeComplete();

		deriveSRTPKeys();
		dtlsListener.onHandshakeComplete();
	}

	@SuppressWarnings("rawtypes")
	@Override
	public void processClientExtensions(Hashtable newClientExtensions) throws IOException {
		super.processClientExtensions(newClientExtensions);

		int chosenProfile = SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80;
		UseSRTPData clientSrtpData = TlsSRTPUtils.getUseSRTPExtension(newClientExtensions);

		for (int profile : clientSrtpData.getProtectionProfiles()) {
			switch (profile) {
			case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_32:
			case SRTPProtectionProfile.SRTP_AES128_CM_HMAC_SHA1_80:
				chosenProfile = profile;
				break;
			default:
			}
		}

		int[] protectionProfiles = { chosenProfile };

		useSRTPData = new UseSRTPData(protectionProfiles, clientSrtpData.getMki());
	}

	private byte[] getKeyingMaterial(int length) {
		return context.exportKeyingMaterial(ExporterLabel.dtls_srtp, null, length);
	}

	private void deriveSRTPKeys() {
		SRTPPolicies srtpPolicies = new SRTPPolicies(useSRTPData.getProtectionProfiles()[0]);
		srtpPolicy = srtpPolicies.getSRTPPolicy();
		srtcpPolicy = srtpPolicies.getSRTCPPolicy();

		int keyLen = srtpPolicy.getEncKeyLength();
		int saltLen = srtpPolicy.getSaltKeyLength();

		srtpMasterClientKey = new byte[keyLen];
		srtpMasterServerKey = new byte[keyLen];
		srtpMasterClientSalt = new byte[saltLen];
		srtpMasterServerSalt = new byte[saltLen];

		byte[] sharedSecret = getKeyingMaterial(2 * (keyLen + saltLen));

		System.arraycopy(sharedSecret, 0, srtpMasterClientKey, 0, keyLen);
		System.arraycopy(sharedSecret, keyLen, srtpMasterServerKey, 0, keyLen);
		System.arraycopy(sharedSecret, 2 * keyLen, srtpMasterClientSalt, 0, saltLen);
		System.arraycopy(sharedSecret, (2 * keyLen + saltLen), srtpMasterServerSalt, 0, saltLen);
	}

	@SuppressWarnings("rawtypes")
	protected TlsCredentialedSigner getRSASignerCredentials() throws IOException {
		Vector clientSigAlgs = context.getSecurityParametersHandshake().getClientSigAlgs();

		SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;

		for (int i = 0; i < clientSigAlgs.size(); ++i) {
			SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm) clientSigAlgs.elementAt(i);

			if (alg.getSignature() == SignatureAlgorithm.rsa) {
				// Just grab the first one we find
				signatureAndHashAlgorithm = alg;
				break;
			}
		}

		if (signatureAndHashAlgorithm == null)
			return null;

		TlsCrypto crypto = context.getCrypto();
		TlsCryptoParameters cryptoParams = new TlsCryptoParameters(context);

		Certificate certificate = WebRTCUtils.LoadCertificateChain(cryptoParams.getServerVersion(), crypto,
				new String[] { WebRTCUtils.CERT_FILE });

		if (!(crypto instanceof BcTlsCrypto))
			return null;

		AsymmetricKeyParameter privateKey = WebRTCUtils.LoadBcPrivateKeyResource(WebRTCUtils.CERT_KEY_FILE);
		return new BcDefaultTlsCredentialedSigner(cryptoParams, (BcTlsCrypto) crypto, privateKey, certificate,
				signatureAndHashAlgorithm);
	}

	protected ProtocolVersion[] getSupportedVersions() {
		return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
	}

	public SRTPPolicy getSRTPPolicy() {
		return srtpPolicy;
	}

	public SRTPPolicy getSRTCPPolicy() {
		return srtcpPolicy;
	}

	public byte[] getSRTPMasterServerKey() {
		return srtpMasterServerKey;
	}

	public byte[] getSRTPMasterServerSalt() {
		return srtpMasterServerSalt;
	}

	public byte[] getSRTPMasterClientKey() {
		return srtpMasterClientKey;
	}

	public byte[] getSRTPMasterClientSalt() {
		return srtpMasterClientSalt;
	}
}
