package jwebrtcpeer.srtp;

public class SRTPTransformEngine {

	private SRTPContextFactory contextFactory;

	private SRTPTransformer srtpTransformer;
	private SRTCPTransformer srtcpTransformer;

	public SRTPTransformEngine(boolean sender, byte[] masterKey, byte[] masterSalt, SRTPPolicy strpPolicy,
			SRTPPolicy srtcpPolicy) {
		contextFactory = new SRTPContextFactory(sender, masterKey, masterSalt, strpPolicy, srtcpPolicy);

		srtpTransformer = new SRTPTransformer(contextFactory);
		srtcpTransformer = new SRTCPTransformer(contextFactory);
	}

	public SRTPTransformer getSrtpTransformer() {
		return srtpTransformer;
	}

	public SRTCPTransformer getSrtcpTransformer() {
		return srtcpTransformer;
	}
}
