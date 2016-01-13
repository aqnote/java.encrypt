package com.madding.shared.encrypt.cert.self.tool;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import com.madding.shared.encrypt.util.StreamUtil;

import sun.security.action.GetPropertyAction;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.Extension;

/**
 * 类X509CertTool.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Nov 18, 2013 11:54:53 AM
 */
public class X509CertTool {

    private static final String CERT_TYPE_X509 = "X.509";
    private static final String BEGIN_CERT     = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT       = "-----END CERTIFICATE-----";
    private static final String lineSeparator  = AccessController.doPrivileged(new GetPropertyAction("line.separator"));

    public static String coverCert2String(Certificate cert) throws CertificateEncodingException {
        String certContent = Base64.encodeBase64String(cert.getEncoded());
        String crtFile = BEGIN_CERT + lineSeparator + certContent + END_CERT;
        return crtFile;
    }

    public static Certificate coverString2Cert(String base64CrtFile) throws CertificateException, IOException {

        byte[] certENcoded = getCertEncoded(base64CrtFile);
        InputStream istream = StreamUtil.bytes2Stream(certENcoded);

        CertificateFactory cf = CertificateFactory.getInstance(CERT_TYPE_X509);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(istream);
        istream.close();
        return cert;
    }

    private static byte[] getCertEncoded(String base64CrtFile) {
        if (StringUtils.isEmpty(base64CrtFile)) {
            return null;
        }

        String tmpBase64CrtFile = base64CrtFile;
        String headLine = BEGIN_CERT + lineSeparator;
        if (base64CrtFile.startsWith(headLine)) {
            tmpBase64CrtFile = StringUtils.removeStart(base64CrtFile, headLine);
        }
        if (tmpBase64CrtFile.endsWith(END_CERT)) {
            tmpBase64CrtFile = StringUtils.removeEnd(tmpBase64CrtFile, END_CERT);
        }

        return Base64.decodeBase64(tmpBase64CrtFile);
    }

    public static Extension getExtension(int[] oid, String value) throws IOException {
        if (oid == null || StringUtils.isBlank(value)) {
            return null;
        }
        ObjectIdentifier loginNameOID = new ObjectIdentifier(oid);
        byte l = (byte) value.length();
        byte f = 0x04;
        byte[] bs = new byte[value.length() + 2];
        bs[0] = f;
        bs[1] = l;
        for (int i = 2; i < bs.length; i++) {
            bs[i] = (byte) value.charAt(i - 2);
        }
        return new Extension(loginNameOID, true, bs);
    }

    public static Extension getExtension(String oid, String value) throws IOException {
        if (oid == null || StringUtils.isBlank(value)) {
            return null;
        }
        ObjectIdentifier loginNameOID = new ObjectIdentifier(oid);
        byte l = (byte) value.length();
        byte f = 0x04;
        byte[] bs = new byte[value.length() + 2];
        bs[0] = f;
        bs[1] = l;
        for (int i = 2; i < bs.length; i++) {
            bs[i] = (byte) value.charAt(i - 2);
        }
        return new Extension(loginNameOID, true, bs);
    }
}
