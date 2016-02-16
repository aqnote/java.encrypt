package com.madding.shared.encrypt.cert.self.loader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import com.madding.shared.encrypt.cert.exception.MadCertException;
import com.madding.shared.encrypt.cert.self.tool.PrivateKeyTool;
import com.madding.shared.encrypt.cert.self.tool.X509CertTool;
import com.madding.shared.encrypt.util.ClassLoaderUtil;
import com.madding.shared.encrypt.util.StreamUtil;

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

    public synchronized static X509Certificate getCaCrt() throws MadCertException, CertificateException, IOException {
        if (cert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_CRT_FILE);
            String b64PrivKey = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            cert = X509CertTool.coverString2Cert(b64PrivKey);
        }
        return cert;
    }

    public synchronized static PrivateKey getCaKey() throws MadCertException {
        if (cakPrivKey == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            String b64PrivKey = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            cakPrivKey = PrivateKeyTool.coverString2PrivateKey(b64PrivKey);
        }
        return cakPrivKey;
    }
}
