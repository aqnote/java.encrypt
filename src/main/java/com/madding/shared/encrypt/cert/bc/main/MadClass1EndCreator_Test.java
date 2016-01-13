package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.x500.X500Name;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.bc.util.X500NameUtil;
import com.madding.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类MadClass1EndCreator_Test.java的实现描述：test服务器证书够找类
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadClass1EndCreator_Test implements MadBCConstant {

    public static final String MAD_CLASS1_END_RADIUS = "/home/madding/output/mad_class1_end_test";

    public static void main(String[] args) throws Exception {
        createNewRadius();
    }

    protected static void createNewRadius() throws Exception {

        String cn = "mad test";
        String email = "madding.lip@gmail.com";
        X500Name subject = X500NameUtil.createClass1EndPrincipal(cn, email);

        KeyPair pKeyPair = MadCaCertLoader.getCaKeyPair(USER_CERT_PASSWD);
        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        Certificate endCert = BCCertGenerator.getIns().createClass1EndCert(subject, keyPair.getPublic(), pKeyPair);
        Certificate[] chain = new Certificate[2];
        chain[0] = endCert;
        chain[1] = MadCaCertLoader.getCaCrt();
        
        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + KEY_SUFFIX));
        MadPKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + CRT_SUFFIX));
        MadPKCSWriter.storeDERFile(endCert, ostream);

        ostream = new FileOutputStream(new File(MAD_CLASS1_END_RADIUS + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(chain, pKeyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("end....");
    }

}
