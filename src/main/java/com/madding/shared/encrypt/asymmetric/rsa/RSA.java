/*
 * Programmer-tools -- A develop code for dever to quickly analyse Copyright (C) 2013-2016 madding.lip
 * <madding.lip@gmail.com>. This library is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation;
 */
package com.madding.shared.encrypt.asymmetric.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.madding.shared.encrypt.ProviderUtil;

/**
 * RSA.java desc：TODO
 * 
 * @author madding.lip Jan 11, 2016 11:55:41 AM
 */
public class RSA {

    public static final String   JCE_PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    public static final String   ALGORITHM    = "RSA";

    private Map<String, KeyPair> keyPairs     = new HashMap<String, KeyPair>();

    static {
        ProviderUtil.addBCProvider();
    }

    public static KeyPair genKeyPair(int bit) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM, JCE_PROVIDER);
            keyPairGen.initialize(bit, new SecureRandom());
            return keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair _genKeyPair(int bit) {
        return _genKeyPair(bit, new SecureRandom());
    }

    public static KeyPair _genKeyPair(int bit, SecureRandom srandom) {
        KeyPairGeneratorSpi keyPairGen = new KeyPairGeneratorSpi();
        keyPairGen.initialize(bit, srandom);
        return keyPairGen.generateKeyPair();
    }

    public PublicKey getPublicKey(String name) {
        KeyPair keyPair = keyPairs.get(name);
        if (keyPair == null) {
            return null;
        }
        return keyPair.getPublic();
    }

}
