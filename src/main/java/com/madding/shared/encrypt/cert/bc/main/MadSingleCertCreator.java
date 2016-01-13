package com.madding.shared.encrypt.cert.bc.main;

import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.JCE_PROVIDER;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.madding.shared.encrypt.cert.dataobject.MadCertificateObject;
import com.madding.shared.encrypt.cert.exception.MadCertException;
import com.madding.shared.encrypt.cert.gen.bak.SingleX509V1Creator;
import com.madding.shared.encrypt.util.MessageUtil;

/**
 * 类CertificateFactory.java的实现描述：证书创建工厂类
 * 
 * @author madding.lip Dec 5, 2013 10:05:31 AM
 */
public class MadSingleCertCreator {

    public static final long   ROOT_CERT_INDATE   = 20 * 365 * 24 * 60L * 60 * 1000L;
    public static final long   CLIENT_CERT_INDATE = 5 * 365 * 24 * 60L * 60 * 1000L;

    public static final String ISSUE_STRING       = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=Mad,  OU=Inc,  CN=device,  Email=madding.lip@gmail.com";
    public static final String SUBJECT_Pattern    = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=Mad,  OU=Inc,  CN={0},  Email={1}";

    static {
        ProviderUtil.addBCProvider();
    }

    public static void create() throws MadCertException {
        KeyPair pair = KeyPairUtil.generateRSAKeyPair();

        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        MadCertificateObject certObject =new MadCertificateObject();
        certObject.setNotBefore(new Date(System.currentTimeMillis()));
        certObject.setNotAfter(new Date(System.currentTimeMillis() + ROOT_CERT_INDATE));
        String subject = MessageUtil.formatMessage(SUBJECT_Pattern, "madding.lip", "madding.lip@gmail.com");
        certObject.setSubject(subject);
        certObject.setIssuer(ISSUE_STRING);
        

        try {
            bOut.write(SingleX509V1Creator.generate(certObject, pair).getEncoded());
            bOut.close();
            InputStream in = new ByteArrayInputStream(bOut.toByteArray());
            CertificateFactory fact = CertificateFactory.getInstance("X.509", JCE_PROVIDER);
            X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(in);
            System.out.println(x509Cert);
            System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
        } catch (CertificateEncodingException e) {
            throw new MadCertException(e);
        } catch (IOException e) {
            throw new MadCertException(e);
        } catch (MadCertException e) {
            throw new MadCertException(e);
        } catch (CertificateException e) {
            throw new MadCertException(e);
        } catch (NoSuchProviderException e) {
            throw new MadCertException(e);
        }
    }

    public static void main(String[] args) throws MadCertException {
        MadSingleCertCreator.create();
    }
}
