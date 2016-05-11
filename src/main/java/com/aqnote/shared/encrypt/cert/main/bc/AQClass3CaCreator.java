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
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSWriter;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类AQClass3CaCreator.java的实现描述：ca构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class AQClass3CaCreator implements BCConstant {

    public static final String MAD_CLASS3_CA = "/Users/madding/output/aqnote_class3_ca";

    public static void main(String[] args) throws Exception {
        createNewChain();
    }

    protected static void createExistChain() throws Exception {

        X509Certificate caCert = CaCertLoader.getCaCrt();
        PrivateKey caPrivKey = CaCertLoader.getCaKeyPair().getPrivate();

        KeyPair curKeyPair = CaCertLoader.getClass3CaKeyPair();

        X509Certificate clientCaCert = BCCertGenerator.getIns().createClass3RootCert(curKeyPair, caPrivKey,
                                                                               (X509Certificate) caCert);
        X509Certificate[] clientCaChain = new X509Certificate[2];
        clientCaChain[0] = clientCaCert;
        clientCaChain[1] = caCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_CLASS3_CA));
        PKCSWriter.storePKCS12File(clientCaChain, curKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad class 3 root created end....");
    }

    protected static void createNewChain() throws Exception {

        X509Certificate caCert = CaCertLoader.getCaCrt();
        PrivateKey pPrivKey = CaCertLoader.getCaKeyPair(USER_CERT_PASSWD).getPrivate();

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate middleCert = BCCertGenerator.getIns().createClass3RootCert(keyPair, pPrivKey, caCert);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = caCert;

        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS3_CA + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS3_CA + CRT_SUFFIX));
        PKCSWriter.storeDERFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS3_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, pPrivKey, USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("mad class 3 root created end....");
    }
}
