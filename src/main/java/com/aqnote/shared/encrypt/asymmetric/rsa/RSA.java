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
package com.aqnote.shared.encrypt.asymmetric.rsa;

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

import com.aqnote.shared.encrypt.ProviderUtil;

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
