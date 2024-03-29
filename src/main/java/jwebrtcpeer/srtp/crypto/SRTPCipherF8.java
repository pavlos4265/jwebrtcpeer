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

import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * SrtpCipherF8 implements Srtp F8 Mode Encryption for 128 bits block cipher. F8
 * Mode AES Encryption algorithm is defined in RFC3711, section 4.1.2.
 *
 * Other than Null Cipher, RFC3711 defined two two encryption algorithms:
 * Counter Mode AES Encryption and F8 Mode AES encryption. Both encryption
 * algorithms are capable to encrypt / decrypt arbitrary length data, and the
 * size of packet data is not required to be a multiple of the cipher block size
 * (128bit). So, no padding is needed.
 *
 * Please note: these two encryption algorithms are specially defined by SRTP.
 * They are not common AES encryption modes, so you will not be able to find a
 * replacement implementation in common cryptographic libraries.
 *
 * As defined by RFC3711: F8 mode encryption is optional.
 *
 * mandatory to impl optional default
 * -------------------------------------------------------------------------
 * encryption AES-CM, NULL AES-f8 AES-CM message integrity HMAC-SHA1 - HMAC-SHA1
 * key derivation (PRF) AES-CM - AES-CM
 *
 *
 * @author Bing SU (nova.su@gmail.com)
 * @author Werner Dittmann <werner.dittmann@t-online.de>
 */
public class SRTPCipherF8 extends SRTPCipher {
	/**
	 * F8 mode encryption context, see RFC3711 section 4.1.2 for detailed
	 * description.
	 */
	static class F8Context {
		public byte[] S;
		public byte[] ivAccent;
		long J;
	}

	/**
	 * Encryption key (k_e)
	 */
	private SecretKeySpec encKey;

	/**
	 * Masked Encryption key (F8 mode specific) (k_e XOR (k_s || 0x555..5))
	 */
	private SecretKeySpec maskedKey;

	private F8Context f8ctx;

	public SRTPCipherF8(Cipher cipher) {
		super(cipher);
	}

	/**
	 * @param k_e encryption key
	 * @param k_s salt key
	 */
	@Override
	public void init(byte[] k_e, byte[] k_s) {
		if (k_e.length != BLKLEN)
			throw new IllegalArgumentException("k_e.length != BLKLEN");
		if (k_s.length > k_e.length)
			throw new IllegalArgumentException("k_s.length > k_e.length");

		encKey = getSecretKey(k_e);

		// XOR the original key with the salt||0x55 to get
		// the special key maskedKey.
		byte[] k_m = new byte[k_e.length];
		int i = 0;
		for (; i < k_s.length; ++i)
			k_m[i] = (byte) (k_e[i] ^ k_s[i]);
		for (; i < k_m.length; ++i)
			k_m[i] = (byte) (k_e[i] ^ 0x55);
		maskedKey = getSecretKey(k_m);
	}

	@Override
	public void setIV(byte[] iv, int opmode) throws GeneralSecurityException {
		if (iv.length != cipher.getBlockSize()) {
			throw new IllegalArgumentException("iv.length != BLKLEN");
		}

		/*
		 * RFC 3711 says we should not encrypt more than 2^32 blocks which is way more
		 * than java array max size, so no checks needed here
		 */
		f8ctx = new F8Context();

		/*
		 * Get memory for the derived IV (IV')
		 */
		f8ctx.ivAccent = new byte[BLKLEN];

		/*
		 * Encrypt the original IV to produce IV'.
		 */
		cipher.init(Cipher.ENCRYPT_MODE, maskedKey);
		cipher.update(iv, 0, iv.length, f8ctx.ivAccent, 0);

		/*
		 * re-init cipher with the "normal" key
		 */
		cipher.init(Cipher.ENCRYPT_MODE, encKey);

		f8ctx.J = 0; // initialize the counter
		f8ctx.S = new byte[BLKLEN]; // get the key stream buffer
	}

	@Override
	public void processAAD(byte[] data, int off, int len) {
		throw new IllegalStateException("F8 mode does not accept AAD");
	}

	@Override
	public int process(byte[] data, int off, int len) throws GeneralSecurityException {
		int inLen = len;

		while (inLen >= BLKLEN) {
			processBlock(f8ctx, data, off, BLKLEN);
			inLen -= BLKLEN;
			off += BLKLEN;
		}

		if (inLen > 0) {
			processBlock(f8ctx, data, off, inLen);
		}

		return len;
	}

	/**
	 * Encrypt / Decrypt a block using F8 Mode AES algorithm, read len bytes data
	 * from in at inOff and write the output into out at outOff
	 *
	 * @param f8ctx F8 encryption context
	 * @param inOut byte array holding the data to be processed
	 * @param off   start offset of the data to be processed inside inOut array
	 * @param len   length of the data to be processed inside inOut array from off
	 */
	private void processBlock(F8Context f8ctx, byte[] inOut, int off, int len) throws ShortBufferException {
		/*
		 * XOR the previous key stream with IV' ( S(-1) xor IV' )
		 */
		for (int i = 0; i < BLKLEN; i++)
			f8ctx.S[i] ^= f8ctx.ivAccent[i];

		/*
		 * Now XOR (S(n-1) xor IV') with the current counter, then increment the counter
		 */
		f8ctx.S[12] ^= f8ctx.J >> 24;
		f8ctx.S[13] ^= f8ctx.J >> 16;
		f8ctx.S[14] ^= f8ctx.J >> 8;
		f8ctx.S[15] ^= f8ctx.J;
		f8ctx.J++;

		/*
		 * Now compute the new key stream using AES encrypt
		 */
		cipher.update(f8ctx.S, 0, f8ctx.S.length, f8ctx.S, 0);

		/*
		 * As the last step XOR the plain text with the key stream to produce the cipher
		 * text.
		 */
		for (int i = 0; i < len; i++)
			inOut[off + i] ^= f8ctx.S[i];
	}
}
