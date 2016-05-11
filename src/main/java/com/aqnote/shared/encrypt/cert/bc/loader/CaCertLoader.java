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
package com.aqnote.shared.encrypt.cert.bc.loader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSReader;
import com.aqnote.shared.encrypt.util.ClassLoaderUtil;
import com.aqnote.shared.encrypt.util.StreamUtil;

/**
 * 类CaCertLoader.java的实现描述：ca文件到内存持久化工具类
 * 
 * @author madding.lip Dec 6, 2013 9:30:09 PM
 */
public class CaCertLoader {

    static {
        ProviderUtil.addBCProvider();
    }

    private static final String    CA_CRT_FILE         = "META-INF/aqnote/root_ca.crt";
    private static final String    CA_KEY_FILE         = "META-INF/aqnote/root_ca.key";
    private static final String    CLASS1_CA_CRT_FILE  = "META-INF/aqnote/class1_ca.crt";
    private static final String    CLASS1_CA_KEY_FILE  = "META-INF/aqnote/class1_ca.key";
    private static final String    CLASS2_CA_CRT_FILE  = "META-INF/aqnote/class2_ca.crt";
    private static final String    CLASS2_CA_KEY_FILE  = "META-INF/aqnote/class2_ca.key";
    private static final String    CLASS_3_CA_CRT_FILE = "META-INF/aqnote/class3_ca.crt";
    private static final String    CLASS_3_CA_KEY_FILE = "META-INF/aqnote/class3_ca.key";

    private static final String    BEGIN_CERT          = "-----BEGIN CERTIFICATE-----\n";
    private static final String    END_CERT            = "-----END CERTIFICATE-----\n";

    private static X509Certificate caCrt;
    private static KeyPair         caKeyPair;
    private static X509Certificate class1CaCrt;
    private static KeyPair         class1CaKeyPair;
    private static X509Certificate class2CaCrt;
    private static KeyPair         class2CaKeyPair;
    private static X509Certificate class3RootCrt;
    private static KeyPair         class3RootKeyPair;

    private static String          b64CaCrt;

    public synchronized static X509Certificate getCaCrt() throws IOException {
        if (caCrt == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_CRT_FILE);
            caCrt = PKCSReader.readCert(is);
            is.close();
        }
        return caCrt;
    }

    public synchronized static String getB64CaCrt() throws IOException {
        if (StringUtils.isBlank(b64CaCrt)) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_CRT_FILE);
            b64CaCrt = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            b64CaCrt = StringUtils.removeStart(b64CaCrt, BEGIN_CERT);
            b64CaCrt = StringUtils.removeEnd(b64CaCrt, END_CERT);
        }
        return b64CaCrt;
    }

    public synchronized static KeyPair getCaKeyPair() throws IOException {
        if (caKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            caKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return caKeyPair;
    }

    public synchronized static KeyPair getCaKeyPair(char[] pwd) throws IOException {
        if (caKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            caKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return caKeyPair;
    }

    public synchronized static X509Certificate getClass1CaCrt() throws IOException {
        if (class1CaCrt == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_CRT_FILE);
            class1CaCrt = PKCSReader.readCert(is);
            is.close();
        }
        return class1CaCrt;
    }

    public synchronized static KeyPair getClass1CaKeyPair() throws IOException {
        if (class1CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_KEY_FILE);
            class1CaKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class1CaKeyPair;
    }

    public synchronized static KeyPair getClass1CaKeyPair(char[] pwd) throws IOException {
        if (class1CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_KEY_FILE);
            class1CaKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class1CaKeyPair;
    }

    public synchronized static X509Certificate getClass2CaCrt() throws IOException {
        if (class2CaCrt == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_CRT_FILE);
            class2CaCrt = PKCSReader.readCert(is);
            is.close();
        }
        return class2CaCrt;
    }

    public synchronized static KeyPair getClass2CaKeyPair() throws IOException {
        if (class2CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_KEY_FILE);
            class2CaKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class2CaKeyPair;
    }

    public synchronized static KeyPair getClass2CaKeyPair(char[] pwd) throws IOException {
        if (class2CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_KEY_FILE);
            class2CaKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class2CaKeyPair;
    }

    public synchronized static X509Certificate getClass3CaCrt() throws IOException {
        if (class3RootCrt == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_CRT_FILE);
            class3RootCrt = PKCSReader.readCert(is);
            is.close();
        }
        return class3RootCrt;
    }

    public synchronized static KeyPair getClass3CaKeyPair() throws IOException {
        if (class3RootKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_KEY_FILE);
            class3RootKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class3RootKeyPair;
    }

    public synchronized static KeyPair getClass3CaKeyPair(char[] pwd) throws IOException {
        if (class3RootKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_KEY_FILE);
            class3RootKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class3RootKeyPair;
    }

}
