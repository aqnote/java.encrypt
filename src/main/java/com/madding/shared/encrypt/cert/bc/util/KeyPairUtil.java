package com.madding.shared.encrypt.cert.bc.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.exception.MadCertException;

public class KeyPairUtil implements MadBCConstant {
    
    static {
        ProviderUtil.addBCProvider();
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair() throws MadCertException {
        
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALG_RSA, JCE_PROVIDER);
            kpGen.initialize(1024, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (NoSuchProviderException e) {
            throw new MadCertException(e);
        }
    }
    
    /**
     * Create a random input bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair(int bit) throws MadCertException {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALG_RSA, JCE_PROVIDER);
            kpGen.initialize(bit, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (NoSuchProviderException e) {
            throw new MadCertException(e);
        }
    }
}
