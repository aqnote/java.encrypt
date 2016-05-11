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
package com.aqnote.shared.encrypt.cert.jdk.loader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.aqnote.shared.encrypt.cert.exception.CertException;
import com.aqnote.shared.encrypt.cert.jdk.tool.PrivateKeyTool;
import com.aqnote.shared.encrypt.cert.jdk.tool.X509CertTool;
import com.aqnote.shared.encrypt.util.ClassLoaderUtil;
import com.aqnote.shared.encrypt.util.StreamUtil;

/**
 * 类CaCertLoader.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 11:33:10 PM
 */
public class CaCertLoader {

    private static final String    CA_CRT_FILE = "META-INF/self_certca/ca.crt";
    private static final String    CA_KEY_FILE = "META-INF/self_certca/ca.key";

    private static X509Certificate cert;
    private static PrivateKey      cakPrivKey;

    public synchronized static X509Certificate getCaCrt() throws CertException, CertificateException, IOException {
        if (cert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_CRT_FILE);
            String b64PrivKey = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            cert = X509CertTool.coverString2Cert(b64PrivKey);
        }
        return cert;
    }

    public synchronized static PrivateKey getCaKey() throws CertException {
        if (cakPrivKey == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            String b64PrivKey = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            cakPrivKey = PrivateKeyTool.coverString2PrivateKey(b64PrivKey);
        }
        return cakPrivKey;
    }
}
