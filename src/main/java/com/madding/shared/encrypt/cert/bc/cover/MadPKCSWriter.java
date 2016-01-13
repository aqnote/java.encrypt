package com.madding.shared.encrypt.cert.bc.cover;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.util.CertificateUtil;

/**
 * 类MadPKCSWriter.java的实现描述：证书持久化工具类
 * 
 * @author madding.lip Dec 6, 2013 7:24:53 PM
 */
public class MadPKCSWriter implements MadBCConstant {

    public static void storePKCS12File(Certificate[] chain, PrivateKey key, char[] pwd, OutputStream ostream)
                                                                                                             throws Exception {
        if (chain == null || key == null || ostream == null) return;

        PKCS12SafeBag[] certSafeBags = new PKCS12SafeBag[chain.length];
        for (int i = chain.length - 1; i > 0; i--) {
            X509Certificate cert = (X509Certificate) chain[i];
            PKCS12SafeBagBuilder safeBagBuilder = new JcaPKCS12SafeBagBuilder(cert);
            safeBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute,
                                           new DERBMPString(CertificateUtil.getSubjectCN(cert)));
            certSafeBags[i] = safeBagBuilder.build();
        }

        X509Certificate cert = (X509Certificate) chain[0];
        String subjectCN = CertificateUtil.getSubjectCN(cert);
        SubjectKeyIdentifier pubKeyId = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(cert.getPublicKey());

        PKCS12SafeBagBuilder safeBagBuilder = new JcaPKCS12SafeBagBuilder(cert);
        safeBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(subjectCN));
        safeBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);
        certSafeBags[0] = safeBagBuilder.build();

        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        // desEDE/id_aes256_CBC
        OutputEncryptor oKeyEncryptor = new JcePKCSPBEOutputEncryptorBuilder(pbeWithSHAAnd3_KeyTripleDES_CBC).setProvider(JCE_PROVIDER).build(pwd);
        PKCS12SafeBagBuilder keySafeBagBuilder = new JcaPKCS12SafeBagBuilder(key, oKeyEncryptor);
        keySafeBagBuilder.addBagAttribute(PKCS12SafeBag.friendlyNameAttribute, new DERBMPString(subjectCN));
        keySafeBagBuilder.addBagAttribute(PKCS12SafeBag.localKeyIdAttribute, pubKeyId);
        pfxPduBuilder.addData(keySafeBagBuilder.build());

        OutputEncryptor oCertEncryptor = new JcePKCSPBEOutputEncryptorBuilder(pbeWithSHAAnd40BitRC2_CBC).setProvider(JCE_PROVIDER).build(pwd);
        pfxPduBuilder.addEncryptedData(oCertEncryptor, certSafeBags);

        // PKCS12PfxPdu pfxPdu = pfxPduBuilder.build(new JcePKCS12MacCalculatorBuilder(idSHA1), pwd);
        PKCS12PfxPdu pfxPdu = pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), pwd);

        ostream.write(pfxPdu.getEncoded(ASN1Encoding.DER));
        ostream.close();
    }

    public static void storePKCS12File(PKCS12PfxPdu pfxPdu, OutputStream ostream) throws Exception {
        if (pfxPdu == null || ostream == null) return;

        ostream.write(pfxPdu.getEncoded(ASN1Encoding.DER));
        ostream.close();
    }

    public static void storePKCS7File(Certificate cert, OutputStream ostream) throws Exception {
        // storePem(cert, ostream, null);
    }

    public static void storePKCS10File(PKCS10CertificationRequest csr, OutputStream ostream) throws Exception {
        StringBuilder csrString = new StringBuilder(CSR_BEGIN + _N);
        csrString.append(Base64.encodeBase64String(csr.getEncoded()) + _N);
        csrString.append(CSR_END);
        ostream.write(csrString.toString().getBytes());
        ostream.close();
    }

    public static void storeDERFile(Certificate cert, OutputStream ostream) throws Exception {
        storePem(cert, ostream, null);
    }

    public static void storeCRLFile(X509CRL x509CRL, OutputStream ostream) throws Exception {
        storePem(x509CRL, ostream, null);
    }

    public static void storeKeyFile(PublicKey pubKey, OutputStream ostream) throws Exception {
        storePem(pubKey, ostream, null);
    }

    public static void storeKeyFile(PrivateKey privKey, OutputStream ostream, char[] passwd) throws Exception {
        storePem(privKey, ostream, passwd);
    }

    public static void storeKeyFile(KeyPair keyPair, OutputStream ostream, char[] passwd) throws Exception {
        storePem(keyPair, ostream, passwd);
    }

    private static void storePem(Object obj, OutputStream ostream, char[] pwd) throws Exception {
        if (obj == null || ostream == null) return;

        PEMWriter pemWriter = new PEMWriter(new PrintWriter(ostream));
        if (pwd == null) {
            pemWriter.writeObject(obj);
        } else {
            JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder(DES_EDE3_CBC).setProvider(JCE_PROVIDER).setSecureRandom(new SecureRandom());
            pemWriter.writeObject(obj, encryptorBuilder.build(pwd));
        }
        pemWriter.flush();
        pemWriter.close();
    }

}
