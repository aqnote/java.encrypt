/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.asymmetric.dsa;

import static com.madding.shared.encrypt.util.ByteUtil.toHexString;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 类DSA.java的实现描述：数字签名/检验的工具
 * 
 * @author madding.lip May 7, 2012 3:38:19 PM
 */
public class DSA {

    private static final Logger       log          = LoggerFactory.getLogger(DSA.class);

    public static final String        JCE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    public static final String        ALGORITHM    = "DSA";

    private Map<String, KeyPairEntry> keyPairs     = new HashMap<String, KeyPairEntry>();

    public static KeyPair genKeyPair(int bit) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM, JCE_PROVIDER);
            keyPairGen.initialize(bit, new SecureRandom());
            return keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey getPublicKey(String name) {
        KeyPairEntry entry = getEntry(name, false);
        if (entry == null) {
            return null;
        }
        return entry.publicKey;
    }

    public void setPublicKey(String name, InputStream istream) throws IOException, RuntimeException {
        setPublicKey(name, getBytes(istream));
    }

    public void setPublicKey(String name, byte[] keyBytes) throws RuntimeException {
        KeyPairEntry entry = getEntry(name, true);
        if (entry.publicKey != null) {
            throw new IllegalArgumentException("duplicated public key for name: " + name);
        }
        entry.publicKey = readPublicKey(keyBytes);
    }

    public PrivateKey getPrivateKey(String name) {
        KeyPairEntry entry = getEntry(name, false);
        if (entry == null) {
            return null;
        }
        return entry.privateKey;
    }

    public void setPrivateKey(String name, InputStream istream) throws IOException, RuntimeException {
        setPrivateKey(name, getBytes(istream));
    }

    public void setPrivateKey(String name, byte[] keyBytes) throws RuntimeException {
        KeyPairEntry entry = getEntry(name, true);
        if (entry.privateKey != null) {
            throw new IllegalArgumentException("duplicated private key for name: " + name);
        }
        entry.privateKey = readPrivateKey(keyBytes);
    }

    private KeyPairEntry getEntry(String name, boolean create) {
        KeyPairEntry entry = (KeyPairEntry) keyPairs.get(name);
        if ((entry == null) && create) {
            entry = new KeyPairEntry();
            keyPairs.put(name, entry);
        }
        return entry;
    }

    private byte[] getBytes(InputStream istream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int amount;
        byte[] buffer = new byte[8192]; // 8k
        while ((amount = istream.read(buffer)) >= 0) {
            baos.write(buffer, 0, amount);
        }
        return baos.toByteArray();
    }

    /**
     * 从字节串中读取public key。
     * 
     * @throws RuntimeException 创建key失败
     */
    public static PublicKey readPublicKey(byte[] keyBytes) throws RuntimeException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            byte[] encodedKey = Base64.decodeBase64(keyBytes);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字节串中读取private key。
     * 
     * @throws RuntimeException 创建key失败
     */
    public static PrivateKey readPrivateKey(byte[] keyBytes) throws RuntimeException {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            byte[] encodedKey = Base64.decodeBase64(keyBytes);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 对指定字符串进行签名。
     * 
     * @param content 要签名的字符串
     * @param keyPairName key pair
     * @return base64编码的签名
     */
    public String sign(String content, String keyPairName) throws RuntimeException {
        return sign(getBytes(content, null), keyPairName);
    }

    /**
     * 对指定字符串进行签名。
     * 
     * @param content 要签名的字符串
     * @param keyPairName key pair
     * @param charset 字符串的编码字符集
     * @return base64编码的签名
     */
    public String sign(String content, String keyPairName, String charset) throws RuntimeException {
        return sign(getBytes(content, charset), keyPairName);
    }

    /**
     * 对指定字节流进行签名。
     * 
     * @param content 要签名的字节流
     * @param keyPairName key pair
     * @return base64编码的签名
     */
    public String sign(byte[] content, String keyPairName) throws RuntimeException {
        KeyPairEntry entry = (KeyPairEntry) keyPairs.get(keyPairName);
        if (entry == null || entry.privateKey == null) {
            return null;
        }

        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(entry.privateKey);
            signature.update((byte[]) content);
            byte[] signed = signature.sign();

            if (log.isDebugEnabled()) {
                log.debug("Java signature[length=" + signed.length + "]: " + toHexString(signed));
            }

            return Base64.encodeBase64String(signed);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 检验content的签名。
     * 
     * @param content 要检验的内容
     * @param signature 签名
     * @param keyPairName key pair
     * @return 如果签名正确，则返回<code>true</code>
     */
    public boolean verify(String content, String signature, String keyPairName) throws RuntimeException {
        return verify(getBytes(content, null), signature, keyPairName);
    }

    /**
     * 检验content的签名。
     * 
     * @param content 要检验的内容
     * @param signature 签名
     * @param keyPairName key pair
     * @param 字符串的编码字符集
     * @return 如果签名正确，则返回<code>true</code>
     */
    public boolean verify(String content, String signature, String keyPairName,
                          String charset) throws RuntimeException {
        return verify(getBytes(content, charset), signature, keyPairName);
    }

    /**
     * 检验content的签名。
     * 
     * @param content 要检验的内容
     * @param signature 签名
     * @param keyPairName key pair
     * @return 如果签名正确，则返回<code>true</code>
     */
    public boolean verify(byte[] content, String signature, String keyPairName) throws RuntimeException {
        KeyPairEntry entry = (KeyPairEntry) keyPairs.get(keyPairName);
        if (entry == null || entry.publicKey == null) {
            return false;
        }

        try {
            byte[] signed = Base64.decodeBase64(signature);

            if (log.isDebugEnabled()) {
                log.debug("Java signature[length=" + signed.length + "]: " + toHexString(signed));
            }

            Signature sign = Signature.getInstance(ALGORITHM);
            sign.initVerify(entry.publicKey);
            sign.update((byte[]) content);

            return sign.verify(signed);
        } catch (InvalidKeyException e) {
            throw new RuntimeException("Could not check content", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not check content", e);
        } catch (SignatureException e) {
            throw new RuntimeException("Could not check content", e);
        }
    }

    /**
     * 取得指定content的字节串。
     * 
     * @throws RuntimeException
     */
    private byte[] getBytes(String content, String charset) throws RuntimeException {
        try {
            if (charset == null || "".equals(charset)) {
                charset = new OutputStreamWriter(new ByteArrayOutputStream()).getEncoding();
                charset = Charset.forName(charset).name();
            }
            return content.getBytes(charset);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Invalid charset: " + charset, e);
        }
    }

    private class KeyPairEntry {

        private PublicKey  publicKey;
        private PrivateKey privateKey;
    }
}
