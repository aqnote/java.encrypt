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
package com.aqnote.shared.encrypt.cert.main.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.pkcs.PKCS12PfxPdu;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSReader;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSWriter;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类AQClass1CaCreator.java的实现描述：ca构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class AQClass1CaCreator implements BCConstant {

    public static String MAD_CLASS1_CA = "/Users/madding/output/aqnote_class1_ca";

    public static void main(String[] args) throws Exception {
        createNewChain();

        PKCS12PfxPdu pfx = PKCSReader.readPKCS12(new FileInputStream(MAD_CLASS1_CA + P12_SUFFIX), USER_CERT_PASSWD);
        System.out.println(pfx.toASN1Structure());
        readByKeyStore(MAD_CLASS1_CA + P12_SUFFIX);
    }

    protected static void createExistChain() throws Exception {

        X509Certificate caCert = CaCertLoader.getCaCrt();
        PrivateKey caPrivKey = CaCertLoader.getCaKeyPair().getPrivate();

        KeyPair pKeyPair = CaCertLoader.getClass1CaKeyPair();
        X509Certificate serverCaCert = BCCertGenerator.getIns().createClass1CaCert(pKeyPair, caPrivKey, caCert);
        X509Certificate[] serverCaChain = new X509Certificate[2];
        serverCaChain[0] = serverCaCert;
        serverCaChain[1] = caCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_CLASS1_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(serverCaChain, pKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad server ca created end....");
    }

    protected static void createNewChain() throws Exception {

        X509Certificate caCert = CaCertLoader.getCaCrt();
        PrivateKey pPrivKey = CaCertLoader.getCaKeyPair(USER_CERT_PASSWD).getPrivate();

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate middleCert = BCCertGenerator.getIns().createClass1CaCert(keyPair, pPrivKey, caCert);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = caCert;

        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS1_CA + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS1_CA + CRT_SUFFIX));
        PKCSWriter.storeDERFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS1_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, pPrivKey, USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("mad server ca created end....");
    }

    protected static void readByKeyStore(String ca) throws Exception {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", JCE_PROVIDER);

        pkcs12Store.load(new FileInputStream(ca), USER_CERT_PASSWD);

        System.out.println("########## KeyStore Dump");

        for (Enumeration<?> en = pkcs12Store.aliases(); en.hasMoreElements();) {
            String alias = (String) en.nextElement();

            if (pkcs12Store.isCertificateEntry(alias)) {
                System.out.println("Certificate Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            } else if (pkcs12Store.isKeyEntry(alias)) {
                System.out.println("Key Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            }
        }

        System.out.println();
    }
}
