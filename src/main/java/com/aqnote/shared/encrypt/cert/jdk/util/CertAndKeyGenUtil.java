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
package com.aqnote.shared.encrypt.cert.jdk.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.aqnote.shared.encrypt.cert.exception.CertException;

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

    public static CertAndKeyGen getKeyGen() throws CertException {

        try {
            CertAndKeyGen gen = new CertAndKeyGen(RSA_KEY_TYPE, MD5WITHRSA_SIG_ALG, null);
            SecureRandom secureRandom = SecureRandom.getInstance(SHA1PRNG_ALG, SUN_PROVIDER);
            gen.setRandom(secureRandom);
            gen.generate(1024);
            return gen;
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        } catch (InvalidKeyException e) {
            throw new CertException(e);
        }
    }
}
