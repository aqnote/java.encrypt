package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.pkcs.PKCS12PfxPdu;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSReader;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.gen.MadBCCertGenerator;

/**
 * 类MadCACreator.java的实现描述：ca构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadClass1CaCreator implements MadBCConstant {

    public static String MAD_CLASS1_CA = "/Users/madding/output/mad_class1_ca";

    public static void main(String[] args) throws Exception {
        createNewChain();

        PKCS12PfxPdu pfx = MadPKCSReader.readPKCS12(new FileInputStream(MAD_CLASS1_CA + P12_SUFFIX), USER_CERT_PASSWD);
        System.out.println(pfx.toASN1Structure());
        readByKeyStore(MAD_CLASS1_CA + P12_SUFFIX);
    }

    protected static void createExistChain() throws Exception {

        X509Certificate caCert = MadCaCertLoader.getCaCrt();
        PrivateKey caPrivKey = MadCaCertLoader.getCaKeyPair().getPrivate();

        KeyPair pKeyPair = MadCaCertLoader.getClass1CaKeyPair();
        Certificate serverCaCert = MadBCCertGenerator.createClass1CaCert(pKeyPair, caPrivKey, caCert);
        Certificate[] serverCaChain = new Certificate[2];
        serverCaChain[0] = serverCaCert;
        serverCaChain[1] = caCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_CLASS1_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(serverCaChain, pKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad server ca created end....");
    }

    protected static void createNewChain() throws Exception {

        X509Certificate caCert = MadCaCertLoader.getCaCrt();
        PrivateKey pPrivKey = MadCaCertLoader.getCaKeyPair(USER_CERT_PASSWD).getPrivate();

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        Certificate middleCert = MadBCCertGenerator.createClass1CaCert(keyPair, pPrivKey, caCert);
        Certificate[] chain = new Certificate[2];
        chain[0] = middleCert;
        chain[1] = caCert;
        
        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS1_CA + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS1_CA + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS1_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(chain, pPrivKey, USER_CERT_PASSWD, ostream);
        ostream.close();
        
        System.out.println("mad server ca created end....");
    }

    protected static void readByKeyStore(String ca) throws Exception {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", JCE_PROVIDER);

        pkcs12Store.load(new FileInputStream(ca), USER_CERT_PASSWD);

        System.out.println("########## KeyStore Dump");

        for (Enumeration<?> en = pkcs12Store.aliases(); en.hasMoreElements();) {
            String alias = (String) en.nextElement();

            if (pkcs12Store.isCertificateEntry(alias)) {
                System.out.println("Certificate Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            } else if (pkcs12Store.isKeyEntry(alias)) {
                System.out.println("Key Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            }
        }

        System.out.println();
    }
}
