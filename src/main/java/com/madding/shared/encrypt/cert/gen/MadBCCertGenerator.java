package com.madding.shared.encrypt.cert.gen;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * 证书创建工厂,用于处理证书的创建工作
 * 
 * @author madding.lip
 */
public class MadBCCertGenerator {

    public static Certificate createRootCaCert(KeyPair keyPair) throws Exception {
        return BCCertGenerator.getIns().createRootCaCert(keyPair);
    }

    public static Certificate createClass3RootCert(KeyPair curKeyPair, PrivateKey caPrivKey, X509Certificate caCert) throws Exception {
        return BCCertGenerator.getIns().createClass3RootCert(curKeyPair, caPrivKey, caCert);
    }

    public static Certificate createClass1CaCert(KeyPair curKeyPair, PrivateKey caPrivKey, X509Certificate caCert) throws Exception {
        return BCCertGenerator.getIns().createClass1CaCert(curKeyPair, caPrivKey, caCert);
    }
    
    public static PKCS10CertificationRequest createCSR(X500Name x500Name, KeyPair keyPair) throws Exception {
        return BCCertGenerator.getIns().createCSR(x500Name, keyPair);
    }

}
