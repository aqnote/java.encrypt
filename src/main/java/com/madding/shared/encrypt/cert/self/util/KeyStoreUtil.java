package com.madding.shared.encrypt.cert.self.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.apache.commons.codec.binary.Base64;

import com.Ostermiller.util.CircularByteBuffer;
import com.madding.shared.encrypt.cert.exception.MadCertException;
import com.madding.shared.encrypt.util.StreamUtil;

/**
 * 类KeyStoreTool.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Nov 18, 2013 12:30:58 PM
 */
public class KeyStoreUtil {

    private static final String PKCS12_STORE_TYPE = "pkcs12";

    public static String coverKeyStore2String(KeyStore keyStore, char[] passwd) throws MadCertException {

        try {
            CircularByteBuffer cbb = new CircularByteBuffer(CircularByteBuffer.INFINITE_SIZE);
            keyStore.store(cbb.getOutputStream(), passwd);
            return Base64.encodeBase64String(StreamUtil.stream2Bytes(cbb.getInputStream()));
        } catch (KeyStoreException e) {
            throw new MadCertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        } catch (IOException e) {
            throw new MadCertException(e);
        }
    }

    public static KeyStore coverString2KeyStore(String base64PKS, String password) throws MadCertException {

        byte[] keyStoreByte = Base64.decodeBase64(base64PKS);
        InputStream istream = StreamUtil.bytes2Stream(keyStoreByte);
        try {
            KeyStore keyStore = KeyStore.getInstance(PKCS12_STORE_TYPE);
            keyStore.load(istream, password.toCharArray());
            istream.close();
            return keyStore;
        } catch (KeyStoreException e) {
            throw new MadCertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        } catch (IOException e) {
            throw new MadCertException(e);
        }
    }

    public static KeyStore createPCSK12KeyStore(String alias, Key key, char[] pwd, Certificate[] chain)throws MadCertException {

        try {
            KeyStore keyStore = KeyStore.getInstance(PKCS12_STORE_TYPE);
            keyStore.load(null, pwd);
            if (pwd == null) {
                keyStore.setKeyEntry(alias, key.getEncoded(), chain);
            } else {
                keyStore.setKeyEntry(alias, key, pwd, chain);
            }
            return keyStore;
        } catch (KeyStoreException e) {
            throw new MadCertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        } catch (IOException e) {
            throw new MadCertException(e);
        }
    }
}
