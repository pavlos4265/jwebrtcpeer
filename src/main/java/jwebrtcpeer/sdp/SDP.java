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

public class SDP {

	private String type;

	// v=
	private String version;

	// o=
	private String originator;

	// s=
	private String sessionName;

	// i=
	private String sessionInformation;

	// t=
	private String time;

	// a=
	private List<String> attributes;

	// media
	private List<MediaDescription> media;

	public SDP() {
		attributes = new ArrayList<String>();
		media = new ArrayList<MediaDescription>();
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getOriginator() {
		return originator;
	}

	public void setOriginator(String originator) {
		this.originator = originator;
	}

	public String getSessionName() {
		return sessionName;
	}

	public void setSessionName(String sessionName) {
		this.sessionName = sessionName;
	}

	public String getSessionInformation() {
		return sessionInformation;
	}

	public void setSessionInformation(String sessionInformation) {
		this.sessionInformation = sessionInformation;
	}

	public String getTime() {
		return time;
	}

	public void setTime(String time) {
		this.time = time;
	}

	public List<String> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<String> attributes) {
		this.attributes = attributes;
	}

	public List<MediaDescription> getMedia() {
		return media;
	}

	public void setMedia(List<MediaDescription> media) {
		this.media = media;
	}
}
