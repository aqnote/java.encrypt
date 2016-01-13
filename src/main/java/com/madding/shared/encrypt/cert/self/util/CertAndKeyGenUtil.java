package com.madding.shared.encrypt.cert.self.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.madding.shared.encrypt.cert.exception.MadCertException;

import sun.security.tools.keytool.CertAndKeyGen;

/**
 * 类PublicKeyCryptoTool.java的实现描述：公钥加密算法工具类
 * 
 * @author madding.lip Dec 4, 2013 2:34:41 PM
 */
public class CertAndKeyGenUtil {

    public static final String SUN_PROVIDER       = "SUN";
    public static final String RSA_KEY_TYPE       = "RSA";
    public static final String SHA1PRNG_ALG       = "SHA1PRNG";
    public static final String MD5WITHRSA_SIG_ALG = "MD5WithRSA";

    public static CertAndKeyGen getKeyGen() throws MadCertException {

        try {
            CertAndKeyGen gen = new CertAndKeyGen(RSA_KEY_TYPE, MD5WITHRSA_SIG_ALG, null);
            SecureRandom secureRandom = SecureRandom.getInstance(SHA1PRNG_ALG, SUN_PROVIDER);
            gen.setRandom(secureRandom);
            gen.generate(1024);
            return gen;
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (NoSuchProviderException e) {
            throw new MadCertException(e);
        } catch (InvalidKeyException e) {
            throw new MadCertException(e);
        }
    }
}
