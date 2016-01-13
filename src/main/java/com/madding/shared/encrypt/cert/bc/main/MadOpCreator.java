package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.pkcs.PKCS12PfxPdu;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSReader;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.gen.MadBCCertGenerator;

/**
 * 类MadOpCreator.java的实现描述：
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadOpCreator implements MadBCConstant {

    public static final String MAD_ROOT_CA = "/home/madding/output/mad_root_ca";

    public static void main(String[] args) throws Exception {
        read();
    }

    protected static void read() throws Exception {
        createNewRootChain();
        
        FileInputStream istream = new FileInputStream(MAD_ROOT_CA + CRT_SUFFIX);
        X509Certificate cert = MadPKCSReader.readCert(istream);
        System.out.println("==================cert====================");
        System.out.println(cert);
        FileOutputStream ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(cert, ostream);
        
        istream = new FileInputStream(MAD_ROOT_CA + KEY_SUFFIX);
        PrivateKey privKey = MadPKCSReader.readPrivateKey(istream, USER_CERT_PASSWD);
        System.out.println("==================key=====================");
        System.out.println(privKey);
        ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(privKey, ostream, USER_CERT_PASSWD);
        
        istream = new FileInputStream(MAD_ROOT_CA + P12_SUFFIX);
        PKCS12PfxPdu pfxPdu = MadPKCSReader.readPKCS12(istream, USER_CERT_PASSWD);
        System.out.println("==================pkcs#12=================");
        System.out.println(privKey);
        ostream = new FileOutputStream(new File(MAD_ROOT_CA + "_1" + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(pfxPdu, ostream);
    }

    protected static void createExistRootChain() throws Exception {

        KeyPair intKeyPair = MadCaCertLoader.getCaKeyPair();
        Certificate clientCaCert = MadBCCertGenerator.createRootCaCert(intKeyPair);
        Certificate[] clientCaChain = new Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_ROOT_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(clientCaChain, intKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad client ca created end....");
    }

    protected static void createNewRootChain() throws Exception {

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        Certificate clientCaCert = MadBCCertGenerator.createRootCaCert(keyPair);
        Certificate[] clientCaChain = new Certificate[1];
        clientCaChain[0] = clientCaCert;

        FileOutputStream oStream = new FileOutputStream(new File(MAD_ROOT_CA + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(clientCaCert, oStream);
        oStream.close();
        
        oStream = new FileOutputStream(new File(MAD_ROOT_CA + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(keyPair.getPrivate(), oStream, USER_CERT_PASSWD);
        oStream.close();
        

        oStream = new FileOutputStream(new File(MAD_ROOT_CA + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(clientCaChain, keyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad client ca created end....");
    }

}
