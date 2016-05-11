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
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSWriter;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.bc.util.X500NameUtil;
import com.aqnote.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类AQClass1EndCreator_Test.java的实现描述：test服务器证书够找类
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class AQClass1EndCreator_Test implements BCConstant {

    public static final String MAD_CLASS1_END_RADIUS = "/home/madding/output/aqnote_class1_end_test";

    public static void main(String[] args) throws Exception {
        createNewRadius();
    }

    protected static void createNewRadius() throws Exception {

        String cn = "mad test";
        String email = "madding.lip@gmail.com";
        X500Name subject = X500NameUtil.createClass1EndPrincipal(cn, email);

        KeyPair pKeyPair = CaCertLoader.getCaKeyPair(USER_CERT_PASSWD);
        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate endCert = BCCertGenerator.getIns().createClass1EndCert(subject, keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = endCert;
        chain[1] = CaCertLoader.getCaCrt();

        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + CRT_SUFFIX));
        PKCSWriter.storeDERFile(endCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, pKeyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("end....");
    }

}
