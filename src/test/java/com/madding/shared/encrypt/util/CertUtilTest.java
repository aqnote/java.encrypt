package com.madding.shared.encrypt.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;

import org.bouncycastle.openssl.PEMWriter;

/**
 * CertUtilTest.java desc：test <code>CertUtil</code>
 * 
 * @author madding.lip May 12, 2014 10:09:15 AM
 */
public class CertUtilTest {

    public static void main(String[] args) throws MalformedURLException {
            Certificate[] certs = CertUtil.getServerCertList(new URL("https://www.alipay.com"));
            int i = 0;
            for (Certificate cer : certs) {
                System.out.println(cer);
    
                FileOutputStream fos;
                try {
                    fos = new FileOutputStream("/home/madding/cert_" + ++i + ".crt");
                    PEMWriter pemWriter = new PEMWriter(new PrintWriter(fos));
                    pemWriter.writeObject(cer);
                    pemWriter.flush();
                    pemWriter.close();
                    fos.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
    
            }
    
        }
}
