/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com>
 * Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.aqnote.com/licenses/LICENSE-1.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.aqnote.shared.encrypt.cert;

import static com.aqnote.shared.encrypt.cert.bc.constant.BCConstant.ALG_SIG_SHA256_RSA;
import static com.aqnote.shared.encrypt.cert.bc.constant.BCConstant.JCE_PROVIDER;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * keytool -genkey -alias caroot -keyalg RSA -keysize 1024 -keystore root.keystore
 */
public class CertificateChainDemo {
   
    public String caName = "caroot";
    public String caPasswd = "hello1234";

    public String keyStorePasswd = "hello1234";

    public String keyStorePath = "/home/madding/output/create_cert/root_intranet.keystore";
   
    public String userDN = "E=madding.lilp@gmail.com, CN=madding.lip, OU=Corp ,O=MAD, L=HangZhou, ST=ZheJiang, C=CN";
    public String userAlias = "madding.lip@gmail.com";    // 用户别名
    
    public CertificateChainDemo() {
    }

    public boolean generateX509Certificate(String userCertPath) {
        try {
            FileInputStream in = new FileInputStream(keyStorePath);
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(in, keyStorePasswd.toCharArray());
            in.close();
           
            // Get CA private key.
            PrivateKey caPrivateKey = (PrivateKey) ks.getKey(caName, caPasswd.toCharArray());
            System.out.println("\nCA private key:\n" + caPrivateKey);

            // Get CA DN.
            Certificate c = ks.getCertificate(caName);
            X509Certificate t = (X509Certificate) c;
            String caDN = t.getIssuerDN().toString();
            // CN:姓氏、名字 OU:组织单位名称 O:组织名称 L:城市、区域 C:国家代码
            System.out.println("\nCA DN:\n" + caDN);

            KeyPair KPair = RSAKeyPairGenDemo.getRSAKeyPair(1024);      
            System.out.println("\nuser private key:\n" + KPair.getPrivate());
            System.out.println("\nuser public key:\n" + KPair.getPublic());
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(new X500Name(caDN), BigInteger.valueOf(1), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)), new X500Name(userDN), KPair.getPublic());
                            
            X509CertificateHolder certHolder = certBuilder.build(new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(KPair.getPrivate()));
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(JCE_PROVIDER).getCertificate(certHolder);

            cert.checkValidity(new Date());
            cert.verify(KPair.getPublic());
            
            ((PKCS12BagAttributeCarrier)cert).setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("x509 cert"));
            
            FileOutputStream out = new FileOutputStream(userCertPath);
            out.write(cert.getEncoded());
            out.close();

            // Add user entry into keystore
            ks.setCertificateEntry(userAlias, cert);
            out = new FileOutputStream(keyStorePath);
            ks.store(out, caPasswd.toCharArray());
            out.close();
       
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    public void listX509CertificateInfo(String certFile) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate x509Cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
            System.out.println("\nIssuerDN:" + x509Cert.getIssuerDN());
            System.out.println("Signature   alg:" + x509Cert.getSigAlgName());
            System.out.println("Version:" + x509Cert.getVersion());
            System.out.println("Serial   Number:" + x509Cert.getSerialNumber());
            System.out.println("Subject   DN:" + x509Cert.getSubjectDN());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean Verify(String certPath) {
        Certificate cert;
        PublicKey caPublicKey;

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream in = new FileInputStream(certPath);
            cert = cf.generateCertificate(in);
            in.close();
            X509Certificate t = (X509Certificate) cert;
            Date timeNow = new Date();
            t.checkValidity(timeNow);

            in = new FileInputStream(keyStorePath);
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(in, keyStorePasswd.toCharArray());
            in.close();
            caPublicKey = ks.getCertificate(caName).getPublicKey();
            System.out.println("\nCA public key:\n" + caPublicKey);
            try {
                cert.verify(caPublicKey);
            } catch (Exception e) {
                System.out.println("no pass.\n");
                e.printStackTrace();
            }
            System.out.println("\npass.\n");
        } catch (CertificateExpiredException e1) {
            e1.printStackTrace();
        } catch (CertificateNotYetValidException e1) {
            e1.printStackTrace();
        } catch (CertificateException e1) {
            e1.printStackTrace();
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        } catch (KeyStoreException e1) {
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        return true;
    }

    public static void main(String args[]) {
        String userCertPath = "/home/madding/output/create_cert/madding.cer";
        CertificateChainDemo ccd = new CertificateChainDemo();
//        ccd.generateX509Certificate(userCertPath);
        ccd.listX509CertificateInfo(userCertPath);
        ccd.Verify(userCertPath);
    }
}