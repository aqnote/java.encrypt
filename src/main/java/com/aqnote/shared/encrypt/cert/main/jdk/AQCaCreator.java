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
package com.aqnote.shared.encrypt.cert.main.jdk;

import java.io.IOException;
import java.security.KeyStore;

import com.aqnote.shared.encrypt.cert.JDKCertSystem;
import com.aqnote.shared.encrypt.cert.dataobject.MadCertDo;
import com.aqnote.shared.encrypt.cert.exception.CertException;
import com.aqnote.shared.encrypt.cert.gen.JDKCertGenerator;
import com.aqnote.shared.encrypt.cert.jdk.util.KeyStoreFileUtil;
import com.aqnote.shared.encrypt.cert.jdk.util.PrivateKeyFileUtil;
import com.aqnote.shared.encrypt.cert.jdk.util.X509CertFileUtil;
import com.aqnote.shared.encrypt.util.CommonUtil;

/**
 * 类AQCaCreator.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 11:09:23 PM
 */
public class AQCaCreator {

    private static final char[] PASSWD = "12345".toCharArray();
    private static final String PATH   = "/home/madding/output/cert/";

    public static void main(String[] args) throws CertException, IOException {
        String pwd = CommonUtil.genRandom(6);
        System.out.println(pwd);

        KeyStore keyStore = JDKCertGenerator.getIns().createRootCert(PASSWD);
        MadCertDo tdPureCertDo = JDKCertSystem.createTDPureCertDo(JDKCertGenerator.CA_ALIAS, keyStore, PASSWD);

        KeyStoreFileUtil.writePkcsFile(tdPureCertDo.getP12File(), PATH + "ca_2.p12");
        PrivateKeyFileUtil.writeKeyFile(tdPureCertDo.getKeyFile(), PATH + "ca_2.key");
        X509CertFileUtil.writeCert(tdPureCertDo.getCertFile(), PATH + "ca_2.crt");
    }
}
