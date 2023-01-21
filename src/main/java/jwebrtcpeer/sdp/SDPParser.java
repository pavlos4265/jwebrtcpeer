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
package jwebrtcpeer.sdp;

import java.util.ArrayList;
import java.util.List;

import jwebrtcpeer.exceptions.BadDescriptionEx;

public class SDPParser {

	public static SDP ParseSDP(String description) throws BadDescriptionEx {
		SDP sdp = new SDP();

		String[] sdpLines = description.split("\\r\\n");

		// parse session description
		int i = 0;
		for (i = 0; i < sdpLines.length; i++) {
			String line = sdpLines[i];

			if (!line.contains("="))
				throw new BadDescriptionEx("bad sdp line " + "(" + (i + 1) + ")");

			String value = line.substring(2);
			char varType = line.charAt(0);
			if (varType == 'm')
				break;

			switch (varType) {
			case 'v':
				sdp.setVersion(value);
				break;
			case 'o':
				sdp.setOriginator(value);
				break;
			case 's':
				sdp.setSessionName(value);
				break;
			case 'i':
				sdp.setSessionInformation(value);
				break;
			case 't':
				sdp.setTime(value);
				break;
			case 'a':
				sdp.getAttributes().add(value);
				break;
			default:
				throw new BadDescriptionEx("unknown value type (" + varType + ") in sdp line " + "(" + (i + 1) + ")");
			}
		}

		// parse media descriptions
		MediaDescription mediaDescription = null;
		for (; i < sdpLines.length; i++) {
			String line = sdpLines[i];

			if (!line.contains("="))
				throw new BadDescriptionEx("bad sdp media line " + "(" + (i + 1) + ")");

			String value = line.substring(2);
			char varType = line.charAt(0);
			switch (varType) {
			case 'm':
				if (mediaDescription != null)
					sdp.getMedia().add(mediaDescription);

				mediaDescription = new MediaDescription();
				mediaDescription.setMediaInfo(value);
				break;
			case 'c':
				mediaDescription.setConnectionInfo(value);
				break;
			case 'a':
				String attributeName = (value.contains(":")) ? value.split(":")[0] : value;
				String attributeValue = (value.contains(":")) ? value.substring(attributeName.length() + 1) : null;

				if (mediaDescription.getAttributes().get(attributeName) == null)
					mediaDescription.getAttributes().put(attributeName, new ArrayList<String>());

				if (attributeValue != null)
					mediaDescription.getAttributes().get(attributeName).add(attributeValue);
				break;
			case 'i':
				mediaDescription.setMediaTitle(value);
				break;
			default:
				throw new BadDescriptionEx(
						"unknown value type (" + varType + ") in sdp media line " + "(" + (i + 1) + ")");
			}
		}

		if (mediaDescription != null)
			sdp.getMedia().add(mediaDescription);

		return sdp;
	}

	public static String ToSDPString(SDP sdp) {
		String description = "";

		if (sdp.getVersion() != null)
			description += "v=" + sdp.getVersion() + "\\r\\n";

		if (sdp.getOriginator() != null)
			description += "o=" + sdp.getOriginator() + "\\r\\n";

		if (sdp.getSessionName() != null)
			description += "s=" + sdp.getSessionName() + "\\r\\n";

		if (sdp.getSessionInformation() != null)
			description += "i=" + sdp.getSessionInformation() + "\\r\\n";

		if (sdp.getTime() != null)
			description += "t=" + sdp.getTime() + "\\r\\n";

		for (String attr : sdp.getAttributes())
			description += "a=" + attr + "\\r\\n";

		for (MediaDescription md : sdp.getMedia()) {
			description += "m=" + md.getMediaInfo() + "\\r\\n";

			if (md.getMediaTitle() != null)
				description += "i=" + md.getMediaTitle() + "\\r\\n";

			if (md.getConnectionInfo() != null)
				description += "c=" + md.getConnectionInfo() + "\\r\\n";

			for (String attrName : md.getAttributes().keySet()) {
				List<String> attrValues = md.getAttributes().get(attrName);

				if (attrValues.size() == 0)
					description += "a=" + attrName + "\\r\\n";
				else {
					for (String attrValue : attrValues) {
						description += "a=" + attrName + ":" + attrValue + "\\r\\n";
					}
				}
			}
		}

		return description;
	}

	public static String ToCandidateString(Candidate candidate) {
		String candidateLine = "candidate:" + candidate.getFoundation() + " " + candidate.getComponentId() + " "
				+ candidate.getTransport() + " " + candidate.getPriority() + " " + candidate.getIpAddress() + " "
				+ candidate.getPort() + " typ " + candidate.getCandidateType();

		for (String attrName : candidate.getAttributes().keySet()) {
			candidateLine += " " + attrName + " " + candidate.getAttributes().get(attrName);
		}

		return candidateLine;
	}

	public static Candidate ParseCandidate(String candidateStr) {
		Candidate candidate = new Candidate();
		String[] args = candidateStr.split(" ");
		candidate.setFoundation(args[0]);
		candidate.setComponentId(args[1]);
		candidate.setTransport(args[2]);
		candidate.setPriority(args[3]);
		candidate.setIpAddress(args[4]);
		candidate.setPort(Integer.parseInt(args[5]));
		candidate.setCandidateType(args[7]);
		for (int i = 8; i < args.length; i += 2) {
			candidate.getAttributes().put(args[i], args[i + 1]);
		}
		return candidate;
	}
}
