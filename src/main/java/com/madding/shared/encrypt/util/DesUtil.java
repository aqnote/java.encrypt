package com.madding.shared.encrypt.util;

import static com.madding.shared.encrypt.log.LogAgg.*;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 类DesEncrypt.java的实现描述：DES加密/解密类
 * 
 * @author madding.lip May 7, 2012 3:04:12 PM
 */
public class DesUtil {

    private static final Logger logger       = LoggerFactory.getLogger(DesUtil.class);

    private static final String ALGORITHM    = "DES";
    private static final String ENCODE_UTF_8 = "UTF-8";

    private static Cipher       encodeCipher;
    private static Cipher       decodeCipher;

    static {
        generateCipher("75229a3c9311d971fa7184d23b665670");
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
        String result = null;
        try {
            if (plaintext == null) {
                return null;
            }
            result = new String(Hex.encodeHex(encodeCipher.doFinal(plaintext.getBytes(ENCODE_UTF_8))));
        } catch (IllegalStateException e) {
            logger.error(MSG(R.F, "encrypt", plaintext, e.getMessage()), e);
        } catch (IllegalBlockSizeException e) {
            logger.error(MSG(R.F, "encrypt", plaintext, e.getMessage()), e);
        } catch (BadPaddingException e) {
            logger.error(MSG(R.F, "encrypt", plaintext, e.getMessage()), e);
        } catch (UnsupportedEncodingException e) {
            logger.error(MSG(R.F, "encrypt", plaintext, e.getMessage()), e);
        } finally {
        }

        return result;
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
        String result = null;
        try {
            byte[] clearByte;
            if (cryptotext == null) {
                return null;
            }
            clearByte = decodeCipher.doFinal(Hex.decodeHex(cryptotext.toCharArray()));
            result = new String(clearByte, ENCODE_UTF_8);
        } catch (IllegalStateException e) {
            logger.error(MSG(R.F, "decrypt", cryptotext, e.getMessage()), e);
        } catch (IllegalBlockSizeException e) {
            logger.error(MSG(R.F, "decrypt", cryptotext, e.getMessage()), e);
        } catch (BadPaddingException e) {
            logger.error(MSG(R.F, "decrypt", cryptotext, e.getMessage()), e);
        } catch (UnsupportedEncodingException e) {
            logger.error(MSG(R.F, "decrypt", cryptotext, e.getMessage()), e);
        } catch (DecoderException e) {
            logger.error(MSG(R.F, "decrypt", cryptotext, e.getMessage()), e);
        } finally {
        }
        return result;
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
