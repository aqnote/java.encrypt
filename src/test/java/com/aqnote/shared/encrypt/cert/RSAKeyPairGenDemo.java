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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAKeyPairGenDemo {

    public final static int PUBLIC_KEY  = 0;

    public final static int PRIVATE_KEY = 1;

    public static KeyPair getRSAKeyPair(int keySize) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            keyGen.initialize(keySize, random);

            KeyPair pair = keyGen.generateKeyPair();
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static boolean SaveKeyFile(KeyPair keyPair, String keyFile, int keyType) {

        boolean succ = true;
        // File fKey = new File(keyFile);
        FileOutputStream os = null;

        try {
            if (keyType != 1 && keyType != 0) {
                throw new Exception("Invalid   keyType!");
            }
            os = new FileOutputStream(keyFile);
            Key key = (keyType == PUBLIC_KEY ? (Key) keyPair.getPublic() : (Key) keyPair.getPrivate());
            os.write(key.getEncoded());

            // ObjectOutputStream objOs = new ObjectOutputStream(os);
            // objOs.writeObject((keyType == PUBLIC_KEY ? (Key) keyPair
            // .getPublic() : (Key) keyPair.getPrivate()));
            // objOs.close();
        } catch (Exception e) {
            e.printStackTrace();
            succ = false;
        }
        return succ;

    }

    @SuppressWarnings("unused")
    public static Key LoadKeyObjFromFile(boolean ispk, String keyFile) {
        Key key = null;
        FileInputStream is = null;
        ObjectInputStream objIs = null;

        try {
            is = new FileInputStream(keyFile);
            byte[] buf = new byte[is.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            is.read(buf);
            EncodedKeySpec ks;
            if (ispk) {
                ks = new PKCS8EncodedKeySpec(buf);

            } else {
                ks = new X509EncodedKeySpec(buf);
            }
            key = (!ispk ? (Key) kf.generatePublic(ks) : (Key) kf.generatePrivate(ks));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                is.close();
            } catch (IOException iex) {
                iex.printStackTrace();
            }
        }
        return key;
    }
}
