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

import static com.aqnote.shared.encrypt.cert.bc.constant.BCConstant.JCE_PROVIDER;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.aqnote.shared.encrypt.cert.exception.CertException;
import com.aqnote.shared.encrypt.cert.gen.SingleX509V1Creator;
import com.aqnote.shared.encrypt.util.MessageUtil;

/**
 * 类AQSingleCertCreator.java的实现描述：证书创建工厂类
 * 
 * @author madding.lip Dec 5, 2013 10:05:31 AM
 */
public class AQSingleCertCreator {

    public static final long   ROOT_CERT_INDATE   = 20 * 365 * 24 * 60L * 60 * 1000L;
    public static final long   CLIENT_CERT_INDATE = 5 * 365 * 24 * 60L * 60 * 1000L;

    public static final String ISSUE_STRING       = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=Mad,  OU=Inc,  CN=device,  Email=madding.lip@gmail.com";
    public static final String SUBJECT_Pattern    = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=Mad,  OU=Inc,  CN={0},  Email={1}";

    static {
        ProviderUtil.addBCProvider();
    }

    public static void create() throws CertException {
        KeyPair pair = KeyPairUtil.generateRSAKeyPair();

        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        MadCertificateObject certObject =new MadCertificateObject();
        certObject.setNotBefore(new Date(System.currentTimeMillis()));
        certObject.setNotAfter(new Date(System.currentTimeMillis() + ROOT_CERT_INDATE));
        String subject = MessageUtil.formatMessage(SUBJECT_Pattern, "madding.lip", "madding.lip@gmail.com");
        certObject.setSubject(subject);
        certObject.setIssuer(ISSUE_STRING);
        

        try {
            bOut.write(SingleX509V1Creator.generate(certObject, pair).getEncoded());
            bOut.close();
            InputStream in = new ByteArrayInputStream(bOut.toByteArray());
            CertificateFactory fact = CertificateFactory.getInstance("X.509", JCE_PROVIDER);
            X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(in);
            System.out.println(x509Cert);
            System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
        } catch (CertificateEncodingException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        } catch (CertException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        }
    }

    public static void main(String[] args) throws CertException {
        AQSingleCertCreator.create();
    }
}
