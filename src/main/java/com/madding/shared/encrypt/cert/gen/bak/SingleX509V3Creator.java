package com.madding.shared.encrypt.cert.gen.bak;

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

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.madding.shared.encrypt.cert.exception.MadCertException;

/**
 * 类SingleX509V3Creator.java的实现描述：v3类型证书生成器
 * 
 * @author madding.lip Dec 5, 2013 9:34:02 AM
 */
public class SingleX509V3Creator implements MadBCConstant {

    public static X509Certificate generate(MadCertificateObject certObject, KeyPair keyPair) throws MadCertException {

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
            throw new MadCertException(e);
        } catch (IllegalStateException e) {
            throw new MadCertException(e);
        } catch (CertIOException e) {
            throw new MadCertException(e);
        } catch (OperatorCreationException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        }
    }
}
