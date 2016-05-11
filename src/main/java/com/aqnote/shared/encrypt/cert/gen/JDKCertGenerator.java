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
package com.aqnote.shared.encrypt.cert.gen;

import static com.aqnote.shared.encrypt.cert.jdk.util.CertAndKeyGenUtil.MD5WITHRSA_SIG_ALG;
import static com.aqnote.shared.encrypt.cert.jdk.util.CertAndKeyGenUtil.getKeyGen;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.exception.CertException;
import com.aqnote.shared.encrypt.cert.jdk.tool.X509CertTool;
import com.aqnote.shared.encrypt.cert.jdk.util.KeyStoreUtil;
import com.aqnote.shared.encrypt.cert.jdk.util.X500NameUtil;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * 证书创建工厂,用于处理证书的创建工作
 * 
 * @author madding.lip
 */
public class JDKCertGenerator {

    public static final String                       CA_ALIAS           = "mad_device";

    public static final long                         ROOT_CERT_INDATE   = 20 * 365 * 24 * 60L * 60 * 1000L;
    public static final long                         CLIENT_CERT_INDATE = 5 * 365 * 24 * 60L * 60 * 1000L;

    private static ThreadLocal<JDKCertGenerator> threadlocal        = new ThreadLocal<JDKCertGenerator>();

    static {
        ProviderUtil.addBCProvider();
    }

    public static JDKCertGenerator getIns() {
        if (threadlocal.get() == null) {
            threadlocal.set(new JDKCertGenerator());
        }
        return threadlocal.get();
    }

    /**
     * 颁布客户端证书
     */
    public KeyStore issueClientCert(X500Name subject, CertificateExtensions exts, String subjectAlias, char[] passwd,
                                    PrivateKey signKey) throws CertException {
        try {
            X509CertInfo certInfo = initCert(subject, exts, CLIENT_CERT_INDATE);

            CertAndKeyGen gen = getKeyGen();
            // 设置公钥
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(gen.getPublicKey()));
            X509CertImpl impl = new X509CertImpl(certInfo);
            // 签发
            impl.sign(signKey, MD5WITHRSA_SIG_ALG);
            // // 验证
            impl.verify(gen.getPublicKey());

            X509Certificate[] cert = new X509Certificate[] { (X509Certificate) impl };

            KeyStore keyStore = KeyStoreUtil.createPCSK12KeyStore(subjectAlias, gen.getPrivateKey(), passwd, cert);
            return keyStore;
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        } catch (InvalidKeyException e) {
            throw new CertException(e);
        } catch (SignatureException e) {
            throw new CertException(e);
        }
    }

    /**
     * 创建根证书
     */
    public KeyStore createRootCert(char[] passwd) throws CertException {

        try {
            CertificateExtensions exts = new CertificateExtensions();
            exts.set("", X509CertTool.getExtension("", ""));
            // CertificateExtensions.NAME
            X509CertInfo certInfo = initCert(X500NameUtil.getIssueName(), null, ROOT_CERT_INDATE);

            // 生成公钥对
            CertAndKeyGen gen = getKeyGen();
            // 设置公钥
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(gen.getPublicKey()));
            X509CertImpl impl = new X509CertImpl(certInfo);
            // 签发
            impl.sign(gen.getPrivateKey(), MD5WITHRSA_SIG_ALG);
            X509Certificate[] certs = new X509Certificate[] { (X509Certificate) impl };
            // // 验证
             impl.verify(gen.getPublicKey());
            KeyStore keyStore = KeyStoreUtil.createPCSK12KeyStore(CA_ALIAS, gen.getPrivateKey(), passwd, certs);
            return keyStore;
        } catch (InvalidKeyException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        } catch (SignatureException e) {
            throw new CertException(e);
        }
    }

    private X509CertInfo initCert(X500Name subject, CertificateExtensions extensions, long indate)
                                                                                                  throws CertException {

        X509CertInfo certInfo = new X509CertInfo();
        try {
            // 设置版本
            certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            // 设置序列号
            certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber((int) new Date().getTime()));
            // 设置颁发者
            certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(X500NameUtil.getIssueName()));
            // 设置主题
            certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
            // 设置有效期
            Date firstDate = new Date();
            Date lastDate = new Date(firstDate.getTime() + indate);
            CertificateValidity interval = new CertificateValidity(firstDate, lastDate);
            certInfo.set(X509CertInfo.VALIDITY, interval);
            // 设置算法
            AlgorithmId algID = AlgorithmId.get(MD5WITHRSA_SIG_ALG);
            certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
            // 设置extensions域
            if (extensions != null) {
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
            }

//            // 设置主题id
//            String cn = subject.getCommonName();
//            String[] cnList = cn.split("\\|");
//            UniqueIdentity subjectUniqueId = new UniqueIdentity(cnList[0].getBytes());
//            certInfo.set(X509CertInfo.SUBJECT_ID, new CertificateSubjectUniqueIdentity(subjectUniqueId));
//            // 设置颁发者id
//            String issueUniqueIdStr = "alibaba";
//            UniqueIdentity issueUniqueId = new UniqueIdentity(issueUniqueIdStr.getBytes());
//            certInfo.set(X509CertInfo.ISSUER_ID, new CertificateIssuerUniqueIdentity(issueUniqueId));
            return certInfo;
        } catch (CertificateException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        }
    }

}
