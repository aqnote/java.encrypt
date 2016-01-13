package com.madding.shared.encrypt.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * 类DesEncrypt.java的实现描述：DES加密/解密类
 * 
 * @author madding.lip May 7, 2012 3:04:12 PM
 */
public class DES {

    private static final String ALGORITHM    = "DES";
    private static final String ENCODE_UTF_8 = "UTF-8";

    private static Cipher       encodeCipher;
    private static Cipher       decodeCipher;

    static {
        generateCipher("www.aqnote.com");
    }
    
    public synchronized static byte[] encrypt(byte[] plaintext) {
        try {
            if (plaintext == null) {
                return null;
            }
            return encodeCipher.doFinal(plaintext);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized static String encrypt(String plaintext) {
        try {
            if (plaintext == null) {
                return null;
            }
            return new String(Hex.encodeHex(encodeCipher.doFinal(plaintext.getBytes(ENCODE_UTF_8))));
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    
    public synchronized static byte[] decrypt(byte[] cryptotext) {
        try {
            if (cryptotext == null) {
                return null;
            }
            return decodeCipher.doFinal(cryptotext);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public synchronized static String decrypt(String cryptotext) {
        try {
            byte[] clearByte;
            if (cryptotext == null) {
                return null;
            }
            clearByte = decodeCipher.doFinal(Hex.decodeHex(cryptotext.toCharArray()));
            return new String(clearByte, ENCODE_UTF_8);
        } catch (IllegalStateException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    // 根据密码生成加密和解密器
    private static void generateCipher(String rawKey) {
        try {
            DESKeySpec dks = new DESKeySpec(rawKey.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            SecretKey deskey = keyFactory.generateSecret(dks);
            encodeCipher = Cipher.getInstance(ALGORITHM);
            encodeCipher.init(Cipher.ENCRYPT_MODE, deskey);
            decodeCipher = Cipher.getInstance(ALGORITHM);
            decodeCipher.init(Cipher.DECRYPT_MODE, deskey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
