/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * 类AESEncrypt.java的实现描述：AES加密类
 * 
 * @author madding.lip May 7, 2012 3:09:01 PM
 */
public class AES {

    public final static String  ALGORITHM        = "AES";
    private static final String ENCODE_UTF_8     = "UTF-8";
    public final static int     DEFAULT_KEY_SIZE = 128;

    private static Cipher       encodeCipher;
    private static Cipher       decodeCipher;

    static {
        // key size: 16 24 32
        generateCipher("www.aqnote.com");
    }

    public static byte[] encrypt(byte[] plaintext) throws RuntimeException {
        try {
            return encodeCipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static String encrypt(String plaintext) throws RuntimeException {
        try {
            if (plaintext == null) {
                return null;
            }
            return new String(Hex.encodeHex(encodeCipher.doFinal(plaintext.getBytes(ENCODE_UTF_8))));
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static byte[] decrypt(byte[] cryptotext) throws RuntimeException {
        try {
            return decodeCipher.doFinal(cryptotext);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static String decrypt(String cryptotext) throws RuntimeException {
        try {
            byte[] clearByte;
            if (cryptotext == null) {
                return null;
            }
            clearByte = decodeCipher.doFinal(Hex.decodeHex(cryptotext.toCharArray()));
            return new String(clearByte, ENCODE_UTF_8);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static void generateCipher(String rawKey) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(rawKey.getBytes(ENCODE_UTF_8), ALGORITHM);
            encodeCipher = Cipher.getInstance(ALGORITHM);
            encodeCipher.init(Cipher.ENCRYPT_MODE, keySpec);
            decodeCipher = Cipher.getInstance(ALGORITHM);
            decodeCipher.init(Cipher.DECRYPT_MODE, keySpec);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

    }

}
