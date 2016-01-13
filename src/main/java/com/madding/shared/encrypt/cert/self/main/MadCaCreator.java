package com.madding.shared.encrypt.cert.self.main;

import java.io.IOException;
import java.security.KeyStore;

import com.madding.shared.encrypt.cert.MadJDKCertSystem;
import com.madding.shared.encrypt.cert.dataobject.MadCertDo;
import com.madding.shared.encrypt.cert.exception.MadCertException;
import com.madding.shared.encrypt.cert.gen.bak.JDKSelfCertGenerator;
import com.madding.shared.encrypt.cert.self.util.KeyStoreFileUtil;
import com.madding.shared.encrypt.cert.self.util.PrivateKeyFileUtil;
import com.madding.shared.encrypt.cert.self.util.X509CertFileUtil;
import com.madding.shared.encrypt.util.CommonUtil;

/**
 * 类MadCaCreator.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 11:09:23 PM
 */
public class MadCaCreator {

    private static final char[] PASSWD = "12345".toCharArray();
    private static final String PATH   = "/home/madding/output/cert/";

    public static void main(String[] args) throws MadCertException, IOException {
        String pwd = CommonUtil.genRandom(6);
        System.out.println(pwd);

        KeyStore keyStore = JDKSelfCertGenerator.getIns().createRootCert(PASSWD);
        MadCertDo tdPureCertDo = MadJDKCertSystem.createTDPureCertDo(JDKSelfCertGenerator.CA_ALIAS, keyStore, PASSWD);

        KeyStoreFileUtil.writePkcsFile(tdPureCertDo.getP12File(), PATH + "ca_2.p12");
        PrivateKeyFileUtil.writeKeyFile(tdPureCertDo.getKeyFile(), PATH + "ca_2.key");
        X509CertFileUtil.writeCert(tdPureCertDo.getCertFile(), PATH + "ca_2.crt");
    }
}
