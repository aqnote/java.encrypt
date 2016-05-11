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
package com.aqnote.shared.encrypt.cert.gen;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.aqnote.shared.encrypt.cert.exception.CertException;

/**
 * 类SingleX509V1Creator.java的实现描述：当一证书签名
 * 
 * @author madding.lip Dec 5, 2013 9:34:02 AM
 */
public class SingleX509V1Creator implements BCConstant {

    public static X509Certificate generate(MadCertificateObject certObject, KeyPair keyPair) throws CertException {

        try {
            X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
                                                                                   new X500Name(certObject.getIssuer()),
                                                                                   BigInteger.valueOf(System.currentTimeMillis()),
                                                                                   certObject.getNotBefore(),
                                                                                   certObject.getNotAfter(),
                                                                                   new X500Name(certObject.getSubject()),
                                                                                   keyPair.getPublic());

            ContentSigner signer = new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().setProvider(JCE_PROVIDER).getCertificate(certBuilder.build(signer));
        } catch (CertificateEncodingException e) {
            throw new CertException(e);
        } catch (IllegalStateException e) {
            throw new CertException(e);
        } catch (OperatorCreationException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        }
    }
}
