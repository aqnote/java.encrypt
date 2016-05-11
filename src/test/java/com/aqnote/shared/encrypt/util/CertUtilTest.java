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
package com.aqnote.shared.encrypt.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;

import org.bouncycastle.openssl.PEMWriter;

import com.aqnote.shared.encrypt.util.CertUtil;

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
