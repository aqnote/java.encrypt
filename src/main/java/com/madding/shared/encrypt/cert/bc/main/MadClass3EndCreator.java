package com.madding.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.HashMap;

import org.bouncycastle.asn1.x500.X500Name;

import com.madding.shared.encrypt.cert.MadBCCertSystem;
import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.bc.util.X500NameUtil;
import com.madding.shared.encrypt.cert.dataobject.MadCertDo;
import com.madding.shared.encrypt.cert.gen.BCCertGenerator;

/**
 * 类MadClientUserCreator.java的实现描述：证书构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadClass3EndCreator implements MadBCConstant {

    public static final String MAD_CLASS_3_END_EMPNO = "/home/madding/output/mad_class3_end_test";

    public static void main(String[] args) throws Exception {
        writeFile();
    }

    protected static void writeString() throws Exception {
        
        String subjectAltName = "madding.lip";
        String cn = subjectAltName;
        String email = "madding.lip@gmail.com";
        String title = "p1|p2|p3";
        MadCertDo tdPureCertDo = MadBCCertSystem.issueClientCert(-1, subjectAltName, cn, email, title, new HashMap<String, String>(), USER_CERT_PASSWD);
        System.out.println(tdPureCertDo.getP12File());
    }

    protected static void writeFile() throws Exception {
        
        String cn = "test";
        String email = "madding.lip@gmail.com";
        String title = "";//"p1|p2|p3|p4";
        X500Name subject = X500NameUtil.createClass3EndPrincipal(cn, email, title);

        KeyPair pKeyPair = MadCaCertLoader.getClass3CaKeyPair(USER_CERT_PASSWD);
        KeyPair endKeyPair = KeyPairUtil.generateRSAKeyPair(1024);

        Certificate endCert = BCCertGenerator.getIns().createClass3EndCert(-1, subject, null, endKeyPair, pKeyPair);
        Certificate[] chain = new Certificate[3];
        chain[0] = endCert;
        chain[1] = MadCaCertLoader.getClass3CaCrt();
        chain[2] = MadCaCertLoader.getCaCrt();

        FileOutputStream oStream = new FileOutputStream(new File(MAD_CLASS_3_END_EMPNO + P12_SUFFIX));
        MadPKCSWriter.storePKCS12File(chain, endKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);

        System.out.println("end....");
    }

}
