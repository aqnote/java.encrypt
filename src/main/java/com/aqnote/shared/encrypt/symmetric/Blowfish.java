/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com>
 * Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.aqnote.com/licenses/LICENSE-1.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.aqnote.shared.encrypt.symmetric;

import static com.aqnote.shared.encrypt.cert.bc.constant.BCConstant.JCE_PROVIDER;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import com.aqnote.shared.encrypt.ProviderUtil;

/**
 * 类Blowfish.java的实现描述：
 * 
 * <pre>
 * Blowfish。这种算法是由 Bruce Schneier 开发的， 
 * 它是一种具有从 32 位到 448 位（都是 8 的整数倍）可变密钥长度的分组密码
 * (Blowfish/CBC/PKCS5Padding)这里使用Blowfish算法、CBC加密模式和PKCS5Padding填充方式，自动补齐8 位字节长度
 * </pre>
 * 
 * @author madding.lip May 8, 2012 2:08:19 PM
 */
public class Blowfish {

	private static final String CIPHER_NAME = "Blowfish/CBC/PKCS5Padding";
	private static final String PROVIDER_NAME = JCE_PROVIDER;
	private static final String DEFAULT_KEY = "www.aqnote.com";
	private static final String DEFAULT_CHARSET = "UTF-8";
	private static Cipher encryptCipher = null;
	private static Cipher decryptCipher = null;
	private static Key key = null;
	private static AlgorithmParameterSpec iv = null;

	static {
		generateCipher(DEFAULT_KEY);
	}

	private static void generateCipher(String rawKey) {
	    ProviderUtil.addBCProvider();
		encryptCipher = instanceCipher(CIPHER_NAME, PROVIDER_NAME);
		decryptCipher = instanceCipher(CIPHER_NAME, PROVIDER_NAME);
		key = generateKey(rawKey);
		iv = generateIV();
		initCipher(encryptCipher, Cipher.ENCRYPT_MODE, key, iv);
		initCipher(decryptCipher, Cipher.DECRYPT_MODE, key, iv);
	}

	/**
	 * 生成密钥
	 * 
	 * @return Key
	 */
	private static Key generateKey(String keyStr) {
		byte[] keyBytes = null;
		try {
			if (keyStr == null) {
				keyBytes = DEFAULT_KEY.getBytes(DEFAULT_CHARSET);
			} else {
				keyBytes = keyStr.getBytes(DEFAULT_CHARSET);
			}
		} catch (UnsupportedEncodingException e) {
		}
		return new SecretKeySpec(keyBytes, "Blowfish");
	}

	/**
	 * 生成算法参数
	 * 
	 * @return AlgorithmParameterSpec
	 */
	private static AlgorithmParameterSpec generateIV() {
		byte[] algorithmBytes = new byte[] { 20, -114, -36, -120, -36, -37, 48,
				92 };
		return new IvParameterSpec(algorithmBytes);
	}

	/**
	 * 实例化算法器
	 * 
	 * @param name
	 *            cipher name
	 * @param provider
	 *            provider name
	 * @return Cipher
	 */
	private static Cipher instanceCipher(String name, String provider) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(name, provider);
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		} catch (NoSuchPaddingException e) {
		}
		return cipher;
	}

	/**
	 * 初始化算法器
	 * 
	 * @param cipher
	 *            Cipher
	 * @param opmode
	 *            operation mode (ENCRYPT_MODE、DECRYPT_MODE、WRAP_MODE 或
	 *            UNWRAP_MODE)
	 * @param key
	 *            Key
	 * @param iv
	 *            AlgorithmParameterSpec
	 */
	private static void initCipher(Cipher cipher, int opmode, Key key,
			AlgorithmParameterSpec iv) {
		try {
			cipher.init(opmode, key, iv);
		} catch (InvalidKeyException e) {
		} catch (InvalidAlgorithmParameterException e) {
		}
	}

	/**
	 * 这个方法必须同步，因为Cipher在doFinal的时候会将自己的状态reset 如果不同步会有线程并发的问题
	 * 
	 * @param b
	 *            要加密的字节数组
	 * @return 加密后的字节数组
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public synchronized static byte[] encrypt(byte[] b)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] buffer = null;
		initCipher(encryptCipher, Cipher.ENCRYPT_MODE, key, iv);
		buffer = encryptCipher.doFinal(b);
		return buffer;
	}

	/**
	 * 这个方法必须同步，因为Cipher在doFinal的时候会将自己的状态reset 如果不同步会有线程并发的问题
	 * 
	 * @param b
	 *            要解密的字节数组
	 * @return 解密后的字节数组
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public synchronized static byte[] decrypt(byte[] b)
			throws IllegalBlockSizeException, BadPaddingException {
		byte[] buffer = null;
		initCipher(decryptCipher, Cipher.DECRYPT_MODE, key, iv);
		buffer = decryptCipher.doFinal(b);
		return buffer;
	}

	/**
	 * @param str
	 *            要加密的字符串
	 * @return String 加密后的字符串
	 */
	public static String encrypt(String str) {
		String result = null;

		if (!StringUtils.isEmpty(str)) {
			try {
				byte[] src = str.getBytes(DEFAULT_CHARSET);
				byte[] enc = encrypt(src);
				result = Base64.encodeBase64String(enc);
			} catch (IllegalBlockSizeException e) {
				throw new RuntimeException(e);
			} catch (BadPaddingException e) {
				throw new RuntimeException(e);
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
		}
		return result;
	}

	/**
	 * @param str
	 *            要解密的字符串
	 * @return String 解密后的字符串
	 */
	public static String decrypt(String str) {
		String result = null;

		if (!StringUtils.isEmpty(str)) {
			try {
				byte[] src = Base64.decodeBase64(str);
				byte[] dec = decrypt(src);
				result = new String(dec, DEFAULT_CHARSET);
			} catch (IllegalBlockSizeException e) {
				throw new RuntimeException(e);
			} catch (BadPaddingException e) {
				throw new RuntimeException(e);
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e);
			}
		}
		return result;
	}

}
