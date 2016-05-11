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
package com.aqnote.shared.encrypt.cert;

import static com.aqnote.shared.encrypt.cert.gen.BCCertGenerator.getIns;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSTransformer;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.bc.util.X500NameUtil;
import com.aqnote.shared.encrypt.cert.dataobject.MadCertDo;

/**
 * 类MadBCCertSystem.java的实现描述：证书生成系统
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class BCCertSystem {

    public static final Logger logger = LoggerFactory.getLogger(BCCertSystem.class);

    static {
        ProviderUtil.addBCProvider();
    }

    // 颁发证书
    public static MadCertDo issueClientCert(long serialNo, String alias, String cn, String email, String title,
                                            Map<String, String> exts, char[] pwd) throws Exception {

        X500Name subject = X500NameUtil.createClass3EndPrincipal(cn, email, title);

        KeyPair caKeyPair = CaCertLoader.getClass3CaKeyPair();

        KeyPair endKeyPair = KeyPairUtil.generateRSAKeyPair();

        X509Certificate endCert = getIns().createClass3EndCert(serialNo, subject, exts, endKeyPair, caKeyPair);

        MadCertDo madCertDo = new MadCertDo();
        madCertDo.setSerialNumber(serialNo);
        madCertDo.setNotBefore(endCert.getNotBefore());
        madCertDo.setNotAfter(endCert.getNotAfter());
        madCertDo.setIssuerDN(endCert.getIssuerDN().toString());
        madCertDo.setSubjectDN(endCert.getSubjectDN().toString());
        madCertDo.setKeyFile(PKCSTransformer.getKeyFileString(endKeyPair.getPrivate(), pwd));
        madCertDo.setKeyPwd(String.valueOf(pwd));

        return madCertDo;
    }

}
