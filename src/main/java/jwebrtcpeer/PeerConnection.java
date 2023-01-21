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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import jwebrtcpeer.exceptions.BadDescriptionEx;
import jwebrtcpeer.sdp.Candidate;
import jwebrtcpeer.sdp.MediaDescription;
import jwebrtcpeer.sdp.SDP;
import jwebrtcpeer.sdp.SDPParser;
import jwebrtcpeer.udpmanager.UDPManager;

public class PeerConnection {

	// Ports for the candidates. If ports are not set, a random one is chosen.
	private int[] ports;

	private String ip;

	private SDP localDescription, remoteDescription;

	private Gson gson;

	private PeerConnectionListener peerConnectionListener;

	private List<UDPManager> udpManagers;

	private List<Candidate> remoteCandidates;

	private boolean disableReceiverReports = false;

	/**
	 * Starts a new peer connection given some options. The options can be null,
	 * empty, or they can be a combination of the following:<br/>
	 * <br/>
	 * 
	 * ipaddress - The ip address of this peer connection. It will be used in the
	 * generated candidates.<br/>
	 * <br/>
	 * ports - The ports used by this peer connection to listen for udp packets. It
	 * can be one port or more separated by commas. If ports are not set, then a
	 * random one will be generated.<br/>
	 * <br/>
	 * disableReceiverReports - If set to true, then no rtcp receiver reports will
	 * be generated. This might be useful if you want to use this peer as a
	 * relay.<br/>
	 * <br/>
	 * 
	 * @param options
	 */
	public PeerConnection(Map<String, String> options) {
		this.gson = new GsonBuilder().disableHtmlEscaping().create();
		this.udpManagers = new ArrayList<>();
		this.remoteCandidates = new ArrayList<>();

		if (options != null)
			parseOptions(options);
	}

	/**
	 * Set the remote description of the peer connection in json format. If the
	 * local description is also set, the candidates are generated.
	 * 
	 * @param remoteDescription
	 * @throws BadDescriptionEx
	 */
	@SuppressWarnings("rawtypes")
	public void setRemoteDescription(String remoteDescription) throws BadDescriptionEx {
		Map offerMap = gson.fromJson(remoteDescription, Map.class);

		checkOfferFormat(offerMap);

		String descType = offerMap.get("type").toString();
		String sdpData = offerMap.get("sdp").toString();

		SDP sdp = SDPParser.ParseSDP(sdpData);
		sdp.setType(descType);

		this.remoteDescription = sdp;

		if (localDescription != null && this.localDescription.getMedia().size() > 0)
			generateCandidates();
	}

	/**
	 * Set the local description of the peer connection in json format. If the
	 * remote description is also set, the candidates are generated.
	 * 
	 * @param localDescription
	 * @throws BadDescriptionEx
	 */
	@SuppressWarnings("rawtypes")
	public void setLocalDescription(String localDescription) throws BadDescriptionEx {
		Map offerMap = gson.fromJson(localDescription, Map.class);

		checkOfferFormat(offerMap);

		String descType = offerMap.get("type").toString();
		String sdpData = offerMap.get("sdp").toString();

		SDP sdp = SDPParser.ParseSDP(sdpData);
		sdp.setType(descType);

		this.localDescription = sdp;

		if (remoteDescription != null && sdp.getMedia().size() > 0)
			generateCandidates();
	}

	@SuppressWarnings("rawtypes")
	private void checkOfferFormat(Map offerMap) throws BadDescriptionEx {
		if (offerMap.get("type") == null)
			throw new BadDescriptionEx("missing type");

		String descType = offerMap.get("type").toString();
		if (!descType.equalsIgnoreCase("offer") && !descType.equalsIgnoreCase("answer"))
			throw new BadDescriptionEx("wrong type");

		if (offerMap.get("sdp") == null)
			throw new BadDescriptionEx("missing sdp data");
	}

	/**
	 * Generates an answer in json format. If the remote description is not set, an
	 * exception is thrown.
	 * 
	 * @return
	 * @throws Exception
	 */
	public String createAnswer() throws Exception {
		if (remoteDescription == null)
			throw new Exception("empty remote description");

		SDP sdp = cloneSDP(remoteDescription);

		// change setup to passive, sendonly to recvonly and set fingerprint
		for (MediaDescription md : sdp.getMedia()) {
			List<String> setupAttr = md.getAttributes().get("setup");
			if (setupAttr == null || setupAttr.size() == 0)
				throw new Exception("missing 'setup' media attribute in remote offer");

			// TODO: support both passive and active
			if (setupAttr.get(0).equalsIgnoreCase("passive"))
				throw new Exception("This implementation currently only supports passive dtls setup.");

			setupAttr.clear();
			setupAttr.add("passive");

			if (md.getAttributes().get("sendonly") != null) {
				md.getAttributes().remove("sendonly");
				md.getAttributes().put("recvonly", new ArrayList<String>());
			} else if (md.getAttributes().get("recvonly") != null) {
				md.getAttributes().remove("recvonly");
				md.getAttributes().put("sendonly", new ArrayList<String>());
			}

			if (md.getAttributes().get("fingerprint") == null)
				throw new Exception("missing fingerprint from remote description");

			String certFingerprint = WebRTCUtils.Fingerprint(WebRTCUtils.CERT_FILE);
			md.getAttributes().get("fingerprint").clear();
			md.getAttributes().get("fingerprint").add("sha-256 " + certFingerprint);
		}

		String description = "{\"type\":\"answer\", \"sdp\":\"" + SDPParser.ToSDPString(sdp) + "\"}";
		return description;
	}

	/**
	 * Not implemented yet.
	 * 
	 * @param offer
	 * @return
	 * @throws Exception
	 */
	public String createOffer() throws Exception {
		// TODO:
		throw new Exception("createOffer is not implemented yet.");
	}

	private SDP cloneSDP(SDP sdp) {
		return gson.fromJson(gson.toJson(sdp), SDP.class);
	}

	private void generateCandidates() {
		List<Candidate> candidates = getCandidateList(localDescription);

		for (Candidate candidate : candidates) {
			String icepwd = remoteDescription.getMedia().get(0).getAttributes().get("ice-pwd").get(0);
			String remoteFingerprint = remoteDescription.getMedia().get(0).getAttributes().get("fingerprint").get(0)
					.split(" ")[1];
			UDPManager udpManager = new UDPManager(candidate.getAttributes().get("ufrag"), icepwd, remoteFingerprint,
					candidate.getPort(), disableReceiverReports, peerConnectionListener);
			udpManager.start();
			udpManagers.add(udpManager);

			if (peerConnectionListener != null)
				peerConnectionListener.onIceCandidate("{\"candidate\":\"" + SDPParser.ToCandidateString(candidate)
						+ "\",\"sdpMid\":\"0\",\"sdpMLineIndex\":0}");
		}
	}

	private List<Candidate> getCandidateList(SDP sdp) {
		List<Candidate> candidates = new ArrayList<>();
		for (int port : ports) {
			String iceufrag = sdp.getMedia().get(0).getAttributes().get("ice-ufrag").get(0);

			// TODO: a better way to generate these ids
			Candidate candidate = new Candidate();
			candidate.setFoundation("1");
			candidate.setComponentId("1");
			candidate.setTransport("udp");
			candidate.setPriority("1");
			candidate.setIpAddress(ip);
			candidate.setPort(port);
			candidate.setCandidateType("host");
			candidate.getAttributes().put("generation", "0");
			candidate.getAttributes().put("ufrag", iceufrag);
			candidate.getAttributes().put("network-cost", "999");
			candidates.add(candidate);
		}

		return candidates;
	}

	/**
	 * Send a rtp or a rtcp packet to the remote peer. The ssrc of the packet should
	 * be one of agreed ones in the exchanged descriptions.
	 * 
	 * @param data
	 * @param length
	 * @param isrtcp
	 * @throws Exception
	 */
	public void sendMedia(byte[] data, int length, boolean isrtcp) throws Exception {
		for (UDPManager udpManager : udpManagers) {
			if (udpManager.isConnected()) {
				udpManager.sendMedia(data, length, isrtcp);
				break;
			}
		}
	}

	public SDP getLocalDescription() {
		return localDescription;
	}

	public SDP getRemoteDescription() {
		return remoteDescription;
	}

	public void setPeerConnectionListener(PeerConnectionListener peerConnectionListener) {
		this.peerConnectionListener = peerConnectionListener;
	}

	@SuppressWarnings("rawtypes")
	public void addIceCandidate(String candidateStr) {
		Map candidateMap = gson.fromJson(candidateStr, Map.class);
		Candidate candidate = SDPParser.ParseCandidate(candidateMap.get("candidate").toString());
		remoteCandidates.add(candidate);
	}

	private void parseOptions(Map<String, String> options) {
		String ip = options.get("ipaddress");
		if (ip != null)
			this.ip = ip;

		String ports = options.get("ports");
		if (ports != null)
			if (ports.contains(",")) {
				String[] p = ports.split(",");
				this.ports = new int[p.length];
				for (int i = 0; i < p.length; i++) {
					this.ports[i] = Integer.parseInt(p[i]);
				}
			} else
				this.ports = new int[] { Integer.parseInt(ports) };

		String disableReceiverReportsOpt = options.get("disableReceiverReports");
		if (disableReceiverReportsOpt != null)
			if (disableReceiverReportsOpt.equalsIgnoreCase("true"))
				disableReceiverReports = true;
			else
				disableReceiverReports = false;
	}
}
