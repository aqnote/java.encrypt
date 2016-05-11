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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;

/**
 * 证书创建工具
 * 
 * @author madding.lip
 */
public class X509CertFileUtil {

    public static void writeCert(String b64cert, String certFileName) throws IOException {

        if (StringUtils.isBlank(b64cert) || StringUtils.isBlank(certFileName)) {
            return;
        }
        FileOutputStream fos1 = new FileOutputStream(certFileName);
        fos1.write(b64cert.getBytes());
        fos1.flush();
        fos1.close();
    }

    /**
     * 根据证书读取 读取模数N
     * 
     * @param crtPath
     * @return
     */
    public static String getModulusByCrt(String crtPath) {
        String crt = "";
        try {
            crt = readX509CertificatePublicKey(crtPath);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = crt.substring(crt.indexOf("modulus:") + "modulus:".length(), crt.indexOf("publicexponent:"));
        return modulus.trim().replace(" ", "");
    }

    /**
     * 根据证书读取公钥e
     * 
     * @param crtPath
     * @return
     */
    public static String getPubExponentByCrt(String crtPath) {

        String crt = "";
        try {
            crt = readX509CertificatePublicKey(crtPath);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String pubExponent = crt.substring(crt.indexOf("publicexponent:") + "publicexponent:".length(), crt.length());
        return pubExponent.trim().replace(" ", "");

    }

    /**
     * 读取X.509证书
     * 
     * @param crtPath 证书路径
     * @return
     * @throws CertificateException
     * @throws IOException
     */
    public static X509Certificate readX509Certificate(String crtPath) throws CertificateException, IOException {

        InputStream inStream = null;

        inStream = new FileInputStream(crtPath);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

        inStream.close();

        return cert;
    }

    /**
     * 读取公钥证书中的公钥（字符串形式）
     * 
     * @param crtPath
     * @return
     * @throws CertificateException
     * @throws IOException
     */
    public static String readX509CertificatePublicKey(String crtPath) throws CertificateException, IOException {

        X509Certificate x509Certificate = readX509Certificate(crtPath);

        PublicKey publicKey = x509Certificate.getPublicKey();

        return publicKey.toString().replace(" ", "");

    }

}
