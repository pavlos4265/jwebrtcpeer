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
package jwebrtcpeer.srtp;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * SrtcpCryptoContext class is the core class of SRTCP implementation. There can
 * be multiple SRTCP sources in one SRTP session. And each SRTCP stream has a
 * corresponding SrtcpCryptoContext object, identified by sender SSRC. In this
 * way, different sources can be protected independently.
 *
 * SrtcpCryptoContext class acts as a manager class and maintains all the
 * information used in SRTCP transformation. It is responsible for deriving
 * encryption/salting/authentication keys from master keys. And it will invoke
 * certain class to encrypt/decrypt (transform/reverse transform) RTCP packets.
 * It will hold a replay check db and do replay check against incoming packets.
 *
 * Refer to section 3.2 in RFC3711 for detailed description of cryptographic
 * context.
 *
 * Cryptographic related parameters, i.e. encryption mode / authentication mode,
 * master encryption key and master salt key are determined outside the scope of
 * SRTP implementation. They can be assigned manually, or can be assigned
 * automatically using some key management protocol, such as MIKEY (RFC3830),
 * SDES (RFC4568) or Phil Zimmermann's ZRTP protocol (RFC6189).
 *
 * @author Bing SU (nova.su@gmail.com)
 * @author Lyubomir Marinov
 */
public class SRTCPCryptoContext extends BaseCryptoContext {
	/**
	 * Index received so far
	 */
	private int receivedIndex = 0;

	/**
	 * Index sent so far
	 */
	private int sentIndex = 0;

	/**
	 * Construct a normal SrtcpCryptoContext based on the given parameters.
	 *
	 * @param ssrc    the RTP SSRC that this SRTCP cryptographic context protects.
	 * @param masterK byte array holding the master key for this SRTCP cryptographic
	 *                context. Refer to chapter 3.2.1 of the RFC about the role of
	 *                the master key.
	 * @param masterS byte array holding the master salt for this SRTCP
	 *                cryptographic context. It is used to computer the
	 *                initialization vector that in turn is input to compute the
	 *                session key, session authentication key and the session salt.
	 * @param policy  SRTP policy for this SRTCP cryptographic context, defined the
	 *                encryption algorithm, the authentication algorithm, etc
	 */
	public SRTCPCryptoContext(int ssrc, byte[] masterK, byte[] masterS, SRTPPolicy policy)
			throws GeneralSecurityException {
		super(ssrc, masterK, masterS, policy);

		deriveSrtcpKeys(masterK, masterS);
	}

	/**
	 * Checks if a packet is a replayed on based on its sequence number. The method
	 * supports a 64 packet history relative to the given sequence number. Sequence
	 * Number is guaranteed to be real (not faked) through authentication.
	 *
	 * @param index index number of the SRTCP packet
	 * @return true if this sequence number indicates the packet is not a replayed
	 *         one, false if not
	 */
	SRTPErrorStatus checkReplay(int index) {
		// compute the index of previously received packet and its
		// delta to the new received packet
		long delta = index - receivedIndex;

		if (delta > 0)
			return SRTPErrorStatus.OK; // Packet not yet received
		else if (-delta >= REPLAY_WINDOW_SIZE)
			return SRTPErrorStatus.REPLAY_OLD; // Packet too old
		else if (((replayWindow >>> (-delta)) & 0x1) != 0)
			return SRTPErrorStatus.REPLAY_FAIL; // Packet already received!
		else
			return SRTPErrorStatus.OK; // Packet not yet received
	}

	/**
	 * Derives the srtcp session keys from the master key.
	 */
	private void deriveSrtcpKeys(byte[] masterKey, byte[] masterSalt) throws GeneralSecurityException {
		SRTPKdf kdf = new SRTPKdf(masterKey, masterSalt, policy);

		// compute the session salt
		kdf.deriveSessionKey(saltKey, SRTPKdf.LABEL_RTCP_SALT);

		// compute the session encryption key
		if (cipher != null) {
			byte[] encKey = new byte[policy.getEncKeyLength()];
			kdf.deriveSessionKey(encKey, SRTPKdf.LABEL_RTCP_ENCRYPTION);
			cipher.init(encKey, saltKey);
		}

		// compute the session authentication key
		if (mac != null) {
			byte[] authKey = new byte[policy.getAuthKeyLength()];
			kdf.deriveSessionKey(authKey, SRTPKdf.LABEL_RTCP_MSG_AUTH);
			AlgorithmParameterSpec spec = null;
			Key key = new SecretKeySpec(authKey, mac.getAlgorithm());
			mac.init(key, spec);
		}
	}

	/**
	 * Performs Counter Mode AES encryption/decryption
	 *
	 * @param pkt the RTP packet to be encrypted/decrypted
	 */
	private void processPacketAesCm(RawPacket pkt, int index) throws GeneralSecurityException {
		int ssrc = getSenderSsrc(pkt);

		/*
		 * Compute the CM IV (refer to chapter 4.1.1 in RFC 3711):
		 *
		 * k_s XX XX XX XX XX XX XX XX XX XX XX XX XX XX SSRC XX XX XX XX index XX XX XX
		 * XX ------------------------------------------------------XOR IV XX XX XX XX
		 * XX XX XX XX XX XX XX XX XX XX 00 00 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
		 */
		ivStore[0] = saltKey[0];
		ivStore[1] = saltKey[1];
		ivStore[2] = saltKey[2];
		ivStore[3] = saltKey[3];

		// The shifts transform the ssrc and index into network order
		ivStore[4] = (byte) (((ssrc >> 24) & 0xff) ^ saltKey[4]);
		ivStore[5] = (byte) (((ssrc >> 16) & 0xff) ^ saltKey[5]);
		ivStore[6] = (byte) (((ssrc >> 8) & 0xff) ^ saltKey[6]);
		ivStore[7] = (byte) ((ssrc & 0xff) ^ saltKey[7]);

		ivStore[8] = saltKey[8];
		ivStore[9] = saltKey[9];

		ivStore[10] = (byte) (((index >> 24) & 0xff) ^ saltKey[10]);
		ivStore[11] = (byte) (((index >> 16) & 0xff) ^ saltKey[11]);
		ivStore[12] = (byte) (((index >> 8) & 0xff) ^ saltKey[12]);
		ivStore[13] = (byte) ((index & 0xff) ^ saltKey[13]);

		ivStore[14] = ivStore[15] = 0;

		// Encrypted part excludes fixed header (8 bytes)
		int payloadOffset = 8;
		int payloadLength = pkt.getLength() - payloadOffset;

		cipher.setIV(ivStore, Cipher.ENCRYPT_MODE);
		cipher.process(pkt.getBuffer(), pkt.getOffset() + payloadOffset, payloadLength);
	}

	private SRTPErrorStatus processPacketAesGcm(RawPacket pkt, int index, boolean authenticationOnly,
			boolean encrypting) {
		int ssrc = getSenderSsrc(pkt);

		/*
		 * Compute the SRTCP GCM IV (refer to section 9.1 in RFC 7714):
		 *
		 * 0 1 2 3 4 5 6 7 8 9 10 11 +--+--+--+--+--+--+--+--+--+--+--+--+ |00|00| SSRC
		 * |00|00|0+SRTCP Idx|---+ +--+--+--+--+--+--+--+--+--+--+--+--+ | |
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | | Encryption Salt |->(+)
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | |
		 * +--+--+--+--+--+--+--+--+--+--+--+--+ | | Initialization Vector |<--+
		 * +--+--+--+--+--+--+--+--+--+--+--+--+
		 */

		ivStore[0] = saltKey[0];
		ivStore[1] = saltKey[1];

		// The shifts transform the ssrc and index into network order
		ivStore[2] = (byte) (((ssrc >> 24) & 0xff) ^ saltKey[2]);
		ivStore[3] = (byte) (((ssrc >> 16) & 0xff) ^ saltKey[3]);
		ivStore[4] = (byte) (((ssrc >> 8) & 0xff) ^ saltKey[4]);
		ivStore[5] = (byte) ((ssrc & 0xff) ^ saltKey[5]);

		ivStore[6] = saltKey[6];
		ivStore[7] = saltKey[7];

		ivStore[8] = (byte) (((index >> 24) & 0xff) ^ saltKey[8]);
		ivStore[9] = (byte) (((index >> 16) & 0xff) ^ saltKey[9]);
		ivStore[10] = (byte) (((index >> 8) & 0xff) ^ saltKey[10]);
		ivStore[11] = (byte) ((index & 0xff) ^ saltKey[11]);

		try {
			cipher.setIV(ivStore, encrypting ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE);

			if (!authenticationOnly) {
				// Mark the SRTCP packet as encrypted
				index = index | 0x80000000;

				// Encrypted part excludes fixed header (8 bytes)
				int payloadOffset = 8;

				cipher.processAAD(pkt.getBuffer(), pkt.getOffset(), payloadOffset);
				writeRoc(index);
				cipher.processAAD(rbStore, 0, 4);

				int processLen = cipher.process(pkt.getBuffer(), pkt.getOffset() + payloadOffset,
						pkt.getLength() - payloadOffset);

				pkt.setLength(processLen + payloadOffset);
			} else {
				int bufferedTagLen = encrypting ? 0 : policy.getAuthTagLength();
				int aadLen = pkt.getLength() - bufferedTagLen;
				if (aadLen < 0) {
					return SRTPErrorStatus.AUTH_FAIL;
				}
				cipher.processAAD(pkt.getBuffer(), pkt.getOffset(), aadLen);
				writeRoc(index);
				cipher.processAAD(rbStore, 0, 4);

				int processLen = cipher.process(pkt.getBuffer(), aadLen, bufferedTagLen);

				pkt.setLength(aadLen + processLen);
			}
		} catch (GeneralSecurityException e) {
			if (encrypting) {
				// logger.debug(() -> "Error encrypting SRTCP packet: " + e.getMessage());
				return SRTPErrorStatus.FAIL;
			} else {
				return SRTPErrorStatus.AUTH_FAIL;
			}
		}
		return SRTPErrorStatus.OK;
	}

	/**
	 * Performs F8 Mode AES encryption/decryption
	 *
	 * @param pkt the RTP packet to be encrypted/decrypted
	 */
	private void processPacketAesF8(RawPacket pkt, int index) throws GeneralSecurityException {
		// 4 bytes of the iv are zero
		// the first byte of the RTP header is not used.
		ivStore[0] = 0;
		ivStore[1] = 0;
		ivStore[2] = 0;
		ivStore[3] = 0;

		// Mark the SRTCP packet as encrypted
		index = index | 0x80000000;

		// set the index and the encrypt flag in network order into IV
		ivStore[4] = (byte) (index >> 24);
		ivStore[5] = (byte) (index >> 16);
		ivStore[6] = (byte) (index >> 8);
		ivStore[7] = (byte) index;

		// The fixed header follows and fills the rest of the IV
		System.arraycopy(pkt.getBuffer(), pkt.getOffset(), ivStore, 8, 8);

		// Encrypted part excludes fixed header (8 bytes), index (4 bytes), and
		// authentication tag (variable according to policy)
		int payloadOffset = 8;
		int payloadLength = pkt.getLength() - (4 + policy.getAuthTagLength());

		cipher.setIV(ivStore, Cipher.ENCRYPT_MODE);
		cipher.process(pkt.getBuffer(), pkt.getOffset() + payloadOffset, payloadLength);
	}

	/**
	 * Transform a SRTCP packet into a RTCP packet. The method is called when an
	 * SRTCP packet was received. Operations done by the method include:
	 * authentication check, packet replay check and decryption. Both encryption and
	 * authentication functionality can be turned off as long as the SrtpPolicy used
	 * in this SrtpCryptoContext requires no encryption and no authentication. Then
	 * the packet will be sent out untouched. However, this is not encouraged. If no
	 * SRTCP feature is enabled, then we shall not use SRTP TransformConnector. We
	 * should use the original method (RTPManager managed transportation) instead.
	 *
	 * @param pkt the received RTCP packet
	 * @return {@link SRTPErrorStatus#OK} if the packet can be accepted or another
	 *         error status if authentication or replay check failed
	 */
	synchronized public SRTPErrorStatus reverseTransformPacket(RawPacket pkt) throws GeneralSecurityException {
		boolean decrypt = false;
		int tagLength = policy.getAuthTagLength();

		if (!validateSRTCPPacketLength(pkt, tagLength))
			/* Too short to be a valid SRTCP packet */
			return SRTPErrorStatus.INVALID_PACKET;

		int indexEflag;

		if (policy.getEncType() == SRTPPolicy.AESGCM_ENCRYPTION) {
			/* For GCM the index is after the tag, rather than before it. */
			indexEflag = getIndex(pkt, 0);
		} else {
			indexEflag = getIndex(pkt, tagLength);
		}

		if ((indexEflag & 0x80000000) == 0x80000000)
			decrypt = true;

		int index = indexEflag & ~0x80000000;

		SRTPErrorStatus err;

		/* Replay control */
		if ((err = checkReplay(index)) != SRTPErrorStatus.OK) {
			return err;
		}

		/* Authenticate the packet */
		if (policy.getAuthType() != SRTPPolicy.NULL_AUTHENTICATION) {
			// get original authentication data and store in tempStore
			pkt.readRegionToBuff(pkt.getLength() - tagLength, tagLength, tempStore);

			// Shrink packet to remove the authentication tag and index
			// because this is part of authenticated data
			pkt.shrink(tagLength + 4);

			// compute, then save authentication in tagStore
			byte[] tagStore = authenticatePacketHmac(pkt, indexEflag);

			// compare authentication tags using constant time comparison
			int nonEqual = 0;
			for (int i = 0; i < tagLength; i++) {
				nonEqual |= (tempStore[i] ^ tagStore[i]);
			}
			if (nonEqual != 0)
				return SRTPErrorStatus.AUTH_FAIL;
		}

		if (decrypt) {
			/* Decrypt the packet using Counter Mode encryption */
			if (policy.getEncType() == SRTPPolicy.AESCM_ENCRYPTION
					|| policy.getEncType() == SRTPPolicy.TWOFISH_ENCRYPTION) {
				processPacketAesCm(pkt, index);
			} else if (policy.getEncType() == SRTPPolicy.AESGCM_ENCRYPTION) {
				pkt.shrink(4); /* Index is processed separately as part of AAD. */
				err = processPacketAesGcm(pkt, index, false, false);
				if (err != SRTPErrorStatus.OK) {
					return err;
				}
			}
			/* Decrypt the packet using F8 Mode encryption */
			else if (policy.getEncType() == SRTPPolicy.AESF8_ENCRYPTION
					|| policy.getEncType() == SRTPPolicy.TWOFISHF8_ENCRYPTION) {
				processPacketAesF8(pkt, index);
			}
		} else if (policy.getEncType() == SRTPPolicy.AESGCM_ENCRYPTION) {
			err = processPacketAesGcm(pkt, index, true, false);
			if (err != SRTPErrorStatus.OK) {
				return err;
			}
		}
		update(index);

		return SRTPErrorStatus.OK;
	}

	/**
	 * Transform a RTCP packet into a SRTCP packet. The method is called when a
	 * normal RTCP packet ready to be sent. Operations done by the transformation
	 * may include: encryption, using either Counter Mode encryption, or F8 Mode
	 * encryption, adding authentication tag, currently HMC SHA1 method. Both
	 * encryption and authentication functionality can be turned off as long as the
	 * SrtpPolicy used in this SrtcpCryptoContext is requires no encryption and no
	 * authentication. Then the packet will be sent out untouched. However, this is
	 * not encouraged. If no SRTP feature is enabled, then we shall not use SRTP
	 * TransformConnector. We should use the original method (RTPManager managed
	 * transportation) instead.
	 *
	 * @param pkt the RTP packet that is going to be sent out
	 */
	synchronized public SRTPErrorStatus transformPacket(RawPacket pkt) throws GeneralSecurityException {
		boolean encrypt = (policy.getEncType() != SRTPPolicy.NULL_ENCRYPTION);
		int index = sentIndex | (encrypt ? 0x80000000 : 0);

		// Grow packet storage in one step
		pkt.grow(4 + policy.getAuthTagLength());

		/* Encrypt the packet using Counter Mode encryption */
		if (policy.getEncType() == SRTPPolicy.AESCM_ENCRYPTION
				|| policy.getEncType() == SRTPPolicy.TWOFISH_ENCRYPTION) {
			processPacketAesCm(pkt, sentIndex);
		}

		/* Encrypt the packet using Galois/Counter Mode encryption */
		else if (policy.getEncType() == SRTPPolicy.AESGCM_ENCRYPTION) {
			/*
			 * N.B.: we have no way to indicate in policy that we want to send non-encrypted
			 * RTCP authenticated with GCM, but that's not generally a thing one wants to do
			 * anyway.
			 */
			processPacketAesGcm(pkt, sentIndex, false, true);
			pkt.append(rbStore, 4);
		}

		/* Encrypt the packet using F8 Mode encryption */
		else if (policy.getEncType() == SRTPPolicy.AESF8_ENCRYPTION
				|| policy.getEncType() == SRTPPolicy.TWOFISHF8_ENCRYPTION) {
			processPacketAesF8(pkt, sentIndex);
		}

		// Authenticate the packet
		// The authenticate method gets the index via parameter and stores
		// it in network order in rbStore variable.
		if (policy.getAuthType() != SRTPPolicy.NULL_AUTHENTICATION) {
			byte[] tagStore = authenticatePacketHmac(pkt, index);
			pkt.append(rbStore, 4);
			pkt.append(tagStore, policy.getAuthTagLength());
		}
		sentIndex++;
		sentIndex &= ~0x80000000; // clear possible overflow

		return SRTPErrorStatus.OK;
	}

	/**
	 * Logs the current state of the replay window, for debugging purposes.
	 */
	private void logReplayWindow(long newIdx) {
		// logger.debug(() -> "Updated replay window with " + newIdx + ". " +
		// SrtpPacketUtils.formatReplayWindow(receivedIndex, replayWindow,
		// REPLAY_WINDOW_SIZE));
	}

	/**
	 * Updates the SRTP packet index. The method is called after all checks were
	 * successful.
	 *
	 * @param index index number of the accepted packet
	 */
	private void update(int index) {
		int delta = index - receivedIndex;

		/* update the replay bit mask */
		if (delta >= REPLAY_WINDOW_SIZE) {
			replayWindow = 1;
			receivedIndex = index;
		} else if (delta > 0) {
			replayWindow <<= delta;
			replayWindow |= 1;
			receivedIndex = index;
		} else {
			replayWindow |= (1L << -delta);
		}

		logReplayWindow(index);
	}
}
