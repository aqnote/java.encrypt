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
package com.aqnote.shared.encrypt.cert.jdk.util;

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
import com.aqnote.shared.encrypt.cert.exception.CertException;
import com.aqnote.shared.encrypt.util.StreamUtil;

/**
 * 类KeyStoreTool.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Nov 18, 2013 12:30:58 PM
 */
public class KeyStoreUtil {

    private static final String PKCS12_STORE_TYPE = "pkcs12";

    public static String coverKeyStore2String(KeyStore keyStore, char[] passwd) throws CertException {

        try {
            CircularByteBuffer cbb = new CircularByteBuffer(CircularByteBuffer.INFINITE_SIZE);
            keyStore.store(cbb.getOutputStream(), passwd);
            return Base64.encodeBase64String(StreamUtil.stream2Bytes(cbb.getInputStream()));
        } catch (KeyStoreException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        }
    }

    public static KeyStore coverString2KeyStore(String base64PKS, String password) throws CertException {

        byte[] keyStoreByte = Base64.decodeBase64(base64PKS);
        InputStream istream = StreamUtil.bytes2Stream(keyStoreByte);
        try {
            KeyStore keyStore = KeyStore.getInstance(PKCS12_STORE_TYPE);
            keyStore.load(istream, password.toCharArray());
            istream.close();
            return keyStore;
        } catch (KeyStoreException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        }
    }

    public static KeyStore createPCSK12KeyStore(String alias, Key key, char[] pwd, Certificate[] chain)throws CertException {

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
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        }
    }
}
