package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.gen.MadBCCertGenerator;

/**
 * 类MadRootCACreator.java的实现描述：
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadRootCaCreator implements MadBCConstant {

    public static final String MAD_ROOT_CA = "/Users/madding/output/mad_root_ca";

    public static void main(String[] args) throws Exception {
        createNewRootChain();
    }

    protected static void createExistRootChain() throws Exception {

        KeyPair intKeyPair = MadCaCertLoader.getCaKeyPair();
        X509Certificate clientCaCert = MadBCCertGenerator.createRootCaCert(intKeyPair);
        X509Certificate[] clientCaChain = new X509Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_ROOT_CA));
        MadPKCSWriter.storePKCS12File(clientCaChain, intKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad client ca created end....");
    }

    protected static void createNewRootChain() throws Exception {

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate clientCaCert = MadBCCertGenerator.createRootCaCert(keyPair);
        X509Certificate[] clientCaChain = new X509Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream ostream = new FileOutputStream(new File(MAD_ROOT_CA + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_ROOT_CA + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(clientCaCert, ostream);

        ostream = new FileOutputStream(new File(MAD_ROOT_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(clientCaChain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();
        System.out.println("mad client ca created end....");
    }

}
