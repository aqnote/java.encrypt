package com.madding.shared.encrypt.cert.bc.cover;

import static com.madding.shared.encrypt.log.LogAgg.MSG;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilderProvider;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.log.LogAgg.R;

/**
 * 类MadPKCSReader.java的实现描述：pkcs读取工具类
 * 
 * @author madding.lip Dec 6, 2013 7:24:53 PM
 */
public class MadPKCSReader implements MadBCConstant {

    public static final Logger                       logger        = LoggerFactory.getLogger(MadPKCSReader.class);

    private static final JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider(JCE_PROVIDER);
    private static final JcaX509CRLConverter         crlConverter  = new JcaX509CRLConverter().setProvider(JCE_PROVIDER);
    private static final JcaPEMKeyConverter          keyConverter  = new JcaPEMKeyConverter().setProvider(JCE_PROVIDER);

    public static PKCS12PfxPdu readPKCS12(InputStream istream, final char[] pwd) {
        if(istream == null || pwd == null) return null;
        
        try {
            PKCS12PfxPdu pfx = new PKCS12PfxPdu(Streams.readAll(istream));

            if (!pfx.isMacValid(new BcPKCS12MacCalculatorBuilderProvider(BcDefaultDigestProvider.INSTANCE), pwd)) {
                logger.error(MSG(R.F, "readPKCS12", "PKCS#12 MAC test failed!"));
                return null;
            }
            return pfx;
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readPKCS12", t.getMessage()), t);
        }
        return null;
    }
    
    public static PKCS10CertificationRequest readCSR(InputStream istream) {
        if(istream == null) return null;

        try {
            Object object = readFile(istream);
            if (object instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) object;
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readCertificate", t.getMessage()), t);
        }
        return null;
    }

    public static X509Certificate readCert(InputStream istream) {
        if(istream == null) return null;
        
        try {
            Object object = readFile(istream);
            if (object instanceof X509CertificateHolder) {
                return certConverter.getCertificate((X509CertificateHolder) object);
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readCertificate", t.getMessage()), t);
        }
        return null;
    }

    public static X509CRL readCRL(InputStream istream) {
        if(istream == null) return null;
        
        try {
            Object object = readFile(istream);
            if (object instanceof X509CRLHolder) {
                return crlConverter.getCRL((X509CRLHolder) object);
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readCRL", t.getMessage()), t);
        }
        return null;
    }

    public static KeyPair readKeyPair(InputStream istream, final char[] pwd) {
        if(istream == null || pwd == null) return null;
        
        try {
            Object object = readFile(istream);
            if (object instanceof PEMEncryptedKeyPair) {
                PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder().build(pwd);
                return keyConverter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(provider));
            } else if (object instanceof PEMKeyPair) {
                return keyConverter.getKeyPair((PEMKeyPair) object);
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readKeyPair", t.getMessage()), t);
        }
        return null;
    }

    public static PublicKey readPublicKey(InputStream istream, final char[] pwd) {
        if(istream == null || pwd == null) return null;
        
        try {
            Object object = readFile(istream);
            if (object instanceof SubjectPublicKeyInfo) {
                return keyConverter.getPublicKey((SubjectPublicKeyInfo) object);
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readPublicKey", t.getMessage()), t);
        }
        return null;
    }

    public static PrivateKey readPrivateKey(InputStream istream, final char[] pwd) {
        if(istream == null || pwd == null) return null;
        
        try {
            Object object = readFile(istream);
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(pwd);
                return keyConverter.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo) object).decryptPrivateKeyInfo(provider));
            } else if (object instanceof PrivateKeyInfo) {
                return keyConverter.getPrivateKey((PrivateKeyInfo) object);
            } else if (object instanceof PEMEncryptedKeyPair) {
                PEMDecryptorProvider provider = new JcePEMDecryptorProviderBuilder().build(pwd);
                return keyConverter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(provider)).getPrivate();
            } else if (object instanceof PEMKeyPair) {
                return keyConverter.getKeyPair((PEMKeyPair) object).getPrivate();
            }
        } catch (Throwable t) {
            logger.error(MSG(R.F, "readPrivateKey", t.getMessage()), t);
        }
        return null;
    }

    private static Object readFile(InputStream istream) throws Exception {
        if (istream == null) return null;
        PEMParser pemParser = new PEMParser(new InputStreamReader(istream));
        Object object = pemParser.readObject();
        pemParser.close();
        return object;
    }

}
