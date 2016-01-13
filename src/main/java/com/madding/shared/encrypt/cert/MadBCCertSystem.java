package com.madding.shared.encrypt.cert;

import static com.madding.shared.encrypt.cert.gen.BCCertGenerator.getIns;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSTransformer;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.bc.util.X500NameUtil;
import com.madding.shared.encrypt.cert.dataobject.MadCertDo;

/**
 * 类MadBCCertSystem.java的实现描述：证书生成系统
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadBCCertSystem {

    public static final Logger logger = LoggerFactory.getLogger(MadBCCertSystem.class);

    static {
        ProviderUtil.addBCProvider();
    }

    // 颁发证书
    public static MadCertDo issueClientCert(long serialNo, String alias, String cn, String email, String title,
                                            Map<String, String> exts, char[] pwd) throws Exception {

        X500Name subject = X500NameUtil.createClass3EndPrincipal(cn, email, title);

        KeyPair caKeyPair = MadCaCertLoader.getClass3CaKeyPair();

        KeyPair endKeyPair = KeyPairUtil.generateRSAKeyPair();

        X509Certificate endCert = getIns().createClass3EndCert(serialNo, subject, exts, endKeyPair, caKeyPair);

        MadCertDo madCertDo = new MadCertDo();
        madCertDo.setSerialNumber(serialNo);
        madCertDo.setNotBefore(endCert.getNotBefore());
        madCertDo.setNotAfter(endCert.getNotAfter());
        madCertDo.setIssuerDN(endCert.getIssuerDN().toString());
        madCertDo.setSubjectDN(endCert.getSubjectDN().toString());
        madCertDo.setKeyFile(MadPKCSTransformer.getKeyFileString(endKeyPair.getPrivate(), pwd));
        madCertDo.setKeyPwd(String.valueOf(pwd));

        return madCertDo;
    }

}
