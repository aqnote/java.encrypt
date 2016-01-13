package com.madding.shared.encrypt.cert.bc.constant;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 类MadBCConstant.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 7, 2013 12:11:16 AM
 */
public interface MadBCConstant {

    public static final String JCE_PROVIDER       = BouncyCastleProvider.PROVIDER_NAME;
    public static final String ALG_RSA            = "RSA";
    public static final String KEY_STORE_TYPE     = "PKCS12";
    public static final String DES_EDE3_CBC       = "DES-EDE3-CBC";
    public static final String SHA1_RSA           = "SHA1WithRSAEncryption";
    public static final String SHA256_RSA         = "SHA256WithRSAEncryption";
    // @depression
    public static final String ALG_SIG_SHA1_RSA   = "SHA1withRSA";
    public static final String ALG_SIG_SHA256_RSA = "SHA256withRSA";

    public static final char[] USER_CERT_PASSWD   = "123456".toCharArray();

    public static final String CRT_SUFFIX         = ".crt";
    public static final String CRL_SUFFIX         = ".crl";
    public static final String KEY_SUFFIX         = ".key";
    public static final String P12_SUFFIX         = ".p12";

    public static final String CSR_BEGIN          = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String CSR_END            = "-----END CERTIFICATE REQUEST-----";
    public static final String _N                 = "\n";
}
