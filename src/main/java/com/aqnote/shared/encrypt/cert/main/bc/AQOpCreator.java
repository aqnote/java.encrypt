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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS12PfxPdu;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSReader;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSWriter;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类AQOpCreator.java的实现描述：
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class AQOpCreator implements BCConstant {

    public static final String MAD_ROOT_CA = "/home/madding/output/aqnote_root_ca";

    public static void main(String[] args) throws Exception {
        read();
    }

    protected static void read() throws Exception {
        createNewRootChain();

        FileInputStream istream = new FileInputStream(MAD_ROOT_CA + CRT_SUFFIX);
        X509Certificate cert = PKCSReader.readCert(istream);
        System.out.println("==================cert====================");
        System.out.println(cert);
        FileOutputStream ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + CRT_SUFFIX));
        PKCSWriter.storeDERFile(cert, ostream);

        istream = new FileInputStream(MAD_ROOT_CA + KEY_SUFFIX);
        PrivateKey privKey = PKCSReader.readPrivateKey(istream, USER_CERT_PASSWD);
        System.out.println("==================key=====================");
        System.out.println(privKey);
        ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(privKey, ostream, USER_CERT_PASSWD);

        istream = new FileInputStream(MAD_ROOT_CA + P12_SUFFIX);
        PKCS12PfxPdu pfxPdu = PKCSReader.readPKCS12(istream, USER_CERT_PASSWD);
        System.out.println("==================pkcs#12=================");
        System.out.println(privKey);
        ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + P12_SUFFIX));
        PKCSWriter.storePKCS12File(pfxPdu, ostream);
    }

    protected static void createExistRootChain() throws Exception {

        KeyPair intKeyPair = CaCertLoader.getCaKeyPair();
        X509Certificate clientCaCert = BCCertGenerator.getIns().createRootCaCert(intKeyPair);
        X509Certificate[] clientCaChain = new X509Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_ROOT_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(clientCaChain, intKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad client ca created end....");
    }

    protected static void createNewRootChain() throws Exception {

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate clientCaCert = BCCertGenerator.getIns().createRootCaCert(keyPair);
        X509Certificate[] clientCaChain = new X509Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_ROOT_CA + CRT_SUFFIX));
        PKCSWriter.storeDERFile(clientCaCert, oStream);
        oStream.close();

        oStream = new FileOutputStream(new File(MAD_ROOT_CA + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair.getPrivate(), oStream, USER_CERT_PASSWD);
        oStream.close();

        oStream = new FileOutputStream(new File(MAD_ROOT_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(clientCaChain, keyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad client ca created end....");
    }

}
