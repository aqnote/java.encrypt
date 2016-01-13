package com.madding.shared.encrypt.cert;

import static com.madding.shared.encrypt.cert.gen.bak.JDKSelfCertGenerator.getIns;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;

import com.madding.shared.encrypt.cert.dataobject.MadCertDo;
import com.madding.shared.encrypt.cert.exception.MadCertException;
import com.madding.shared.encrypt.cert.self.loader.CaCertLoader;
import com.madding.shared.encrypt.cert.self.tool.PrivateKeyTool;
import com.madding.shared.encrypt.cert.self.tool.X509CertTool;
import com.madding.shared.encrypt.cert.self.util.KeyStoreUtil;
import com.madding.shared.encrypt.cert.self.util.X500NameUtil;

/**
 * 类MadJDKCertSystem.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadJDKCertSystem {

    // 颁发证书
    public static MadCertDo issueClientCert(String alias, String cn, String email, List<String> extList, char[] pwd) throws MadCertException {

        try {
            CertificateExtensions exts = null;
            if (extList != null && extList.size() > 0) {
                exts = new CertificateExtensions();
                for (String ext : extList) {
                    String[] split = ext.split("\\|");
                    if (split == null || split.length < 3) {
                        continue;
                    }
                    exts.set(split[0], X509CertTool.getExtension(split[1], split[2]));
                }
            }

            X500Name subject = X500NameUtil.getSubjectName(cn, email);
            PrivateKey caPrivKey = CaCertLoader.getCaKey();
            KeyStore keyStore = getIns().issueClientCert(subject, exts, alias, pwd, caPrivKey);

            return createTDPureCertDo(alias, keyStore, pwd);
        } catch (IOException e) {
            throw new MadCertException(e);
        }
    }

    public static MadCertDo createTDPureCertDo(String alias, KeyStore keyStore, char[] passwd) throws MadCertException {

        MadCertDo tdPureCertDo = new MadCertDo();
        try {
            // set crt file
            Certificate cert = keyStore.getCertificate(alias);
            tdPureCertDo.setCertFile(X509CertTool.coverCert2String(cert));
            // serial no
            X509Certificate X509Cert = (X509Certificate) cert;
            tdPureCertDo.setSerialNumber(X509Cert.getSerialNumber().longValue());
            // issue dn
            tdPureCertDo.setIssuerDN(X509Cert.getIssuerDN().toString());
            // subject dn
            tdPureCertDo.setSubjectDN(X509Cert.getSubjectDN().toString());
            // set key file
            Key key = keyStore.getKey(alias, passwd);
            tdPureCertDo.setKeyFile(PrivateKeyTool.coverPrivateKey2String(key));
            // set p12 file
            String p12file = KeyStoreUtil.coverKeyStore2String(keyStore, passwd);
            tdPureCertDo.setP12File(p12file);
            // set p12 pwd
            tdPureCertDo.setP12Pwd(String.valueOf(passwd));
        } catch (UnrecoverableKeyException e) {
            throw new MadCertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (KeyStoreException e) {
            throw new MadCertException(e);
        } catch (CertificateEncodingException e) {
            throw new MadCertException(e);
        }

        return tdPureCertDo;
    }
}
