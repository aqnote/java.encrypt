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
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.aqnote.shared.encrypt.cert.exception.CertException;

/**
 * 类SingleX509V3Creator.java的实现描述：v3类型证书生成器
 * 
 * @author madding.lip Dec 5, 2013 9:34:02 AM
 */
public class SingleX509V3Creator implements BCConstant {

    public static X509Certificate generate(MadCertificateObject certObject, KeyPair keyPair) throws CertException {

        try {
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                                                                                   new X500Name(certObject.getIssuer()),
                                                                                   BigInteger.valueOf(System.currentTimeMillis()),
                                                                                   certObject.getNotBefore(),
                                                                                   certObject.getNotAfter(),
                                                                                   new X500Name(certObject.getSubject()),
                                                                                   keyPair.getPublic());

            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                                                                            | KeyUsage.keyEncipherment));
            certBuilder.addExtension(Extension.subjectAlternativeName, false,
                                     new GeneralNames(new GeneralName(GeneralName.rfc822Name, "trust_device")));
            ContentSigner signer = new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().setProvider(JCE_PROVIDER).getCertificate(certBuilder.build(signer));
        } catch (CertificateEncodingException e) {
            throw new CertException(e);
        } catch (IllegalStateException e) {
            throw new CertException(e);
        } catch (CertIOException e) {
            throw new CertException(e);
        } catch (OperatorCreationException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        }
    }
}
