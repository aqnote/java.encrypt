package com.madding.shared.encrypt.cert.gen.bak;

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

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.madding.shared.encrypt.cert.exception.MadCertException;

/**
 * 类SingleX509V1Creator.java的实现描述：当一证书签名
 * 
 * @author madding.lip Dec 5, 2013 9:34:02 AM
 */
public class SingleX509V1Creator implements MadBCConstant {

    public static X509Certificate generate(MadCertificateObject certObject, KeyPair keyPair) throws MadCertException {

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
            throw new MadCertException(e);
        } catch (IllegalStateException e) {
            throw new MadCertException(e);
        } catch (OperatorCreationException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        }
    }
}
