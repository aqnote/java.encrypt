package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.gen.MadBCCertGenerator;

/**
 * 类MadCACreator.java的实现描述：ca构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadClass3CaCreator implements MadBCConstant {

    public static final String MAD_CLASS3_CA = "/Users/madding/output/mad_class3_ca";

    public static void main(String[] args) throws Exception {
        createNewChain();
    }

    protected static void createExistChain() throws Exception {

        Certificate caCert = MadCaCertLoader.getCaCrt();
        PrivateKey caPrivKey = MadCaCertLoader.getCaKeyPair().getPrivate();

        KeyPair curKeyPair = MadCaCertLoader.getClass3CaKeyPair();

        Certificate clientCaCert = MadBCCertGenerator.createClass3RootCert(curKeyPair, caPrivKey,
                                                                           (X509Certificate) caCert);
        Certificate[] clientCaChain = new Certificate[2];
        clientCaChain[0] = clientCaCert;
        clientCaChain[1] = caCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_CLASS3_CA));
        MadPKCSWriter.storePKCS12File(clientCaChain, curKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad class 3 root created end....");
    }

    protected static void createNewChain() throws Exception {

        X509Certificate caCert = MadCaCertLoader.getCaCrt();
        PrivateKey pPrivKey = MadCaCertLoader.getCaKeyPair(USER_CERT_PASSWD).getPrivate();

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        Certificate middleCert = MadBCCertGenerator.createClass3RootCert(keyPair, pPrivKey, caCert);
        Certificate[] chain = new Certificate[2];
        chain[0] = middleCert;
        chain[1] = caCert;
        
        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS3_CA + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS3_CA + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS3_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(chain, pPrivKey, USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("mad class 3 root created end....");
    }
}
