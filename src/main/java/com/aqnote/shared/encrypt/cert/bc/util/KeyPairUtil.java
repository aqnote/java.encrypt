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
package com.aqnote.shared.encrypt.cert.bc.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;
import com.aqnote.shared.encrypt.cert.exception.CertException;

public class KeyPairUtil implements BCConstant {
    
    static {
        ProviderUtil.addBCProvider();
    }

    /**
     * Create a random 1024 bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair() throws CertException {
        
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALG_RSA, JCE_PROVIDER);
            kpGen.initialize(1024, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        }
    }
    
    /**
     * Create a random input bit RSA key pair
     */
    public static KeyPair generateRSAKeyPair(int bit) throws CertException {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(ALG_RSA, JCE_PROVIDER);
            kpGen.initialize(bit, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        }
    }
}
