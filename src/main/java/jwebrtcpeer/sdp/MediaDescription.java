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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MediaDescription {

	// m=
	private String mediaInfo;

	// i=
	private String mediaTitle;

	// c=
	private String connectionInfo;

	// a=
	private Map<String, List<String>> attributes;

	public MediaDescription() {
		attributes = new HashMap<String, List<String>>();
	}

	public String getMediaInfo() {
		return mediaInfo;
	}

	public void setMediaInfo(String mediaInfo) {
		this.mediaInfo = mediaInfo;
	}

	public String getConnectionInfo() {
		return connectionInfo;
	}

	public void setConnectionInfo(String connectionInfo) {
		this.connectionInfo = connectionInfo;
	}

	public Map<String, List<String>> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, List<String>> attributes) {
		this.attributes = attributes;
	}

	public String getMediaTitle() {
		return mediaTitle;
	}

	public void setMediaTitle(String mediaTitle) {
		this.mediaTitle = mediaTitle;
	}
}
