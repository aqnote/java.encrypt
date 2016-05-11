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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import sun.misc.BASE64Decoder;

//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.security.cert.Certificate;
//import java.security.cert.CertificateException;
//import java.security.cert.CertificateFactory;
//
//import sun.misc.BASE64Decoder;

/**
 * 从base64文件中创建证书
 * 
 * @author madding.lip
 */
public class CreateCertFromFile {

    public static void main(String[] args) throws IOException, CertificateException {

        String certStr = "MIIFeTCCBGGgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBxjELMAkGA1UEBhMCTk8"
                         + "xDTALBgNVBAgTBE9zbG8xDTALBgNVBAcTBE9zbG8xIjAgBgNVBAoTGVdvcmxkIF"
                         + "dpZGUgV2ViIENvbnNvcnRpdW0xNjA0BgNVBAsTLXczYy13aWRnZXRzLWRpZ3NpZ"
                         + "y10ZXN0c3VpdGUgcm9vdCBjZXJ0aWZpY2F0ZTEbMBkGA1UEAxMSaHR0cDovL3d3"
                         + "dy53My5vcmcvMSAwHgYJKoZIhvcNAQkBFhFzdHVhcnRrQG9wZXJhLmNvbTAeFw0"
                         + "xMDA5MjQwODQ2MTFaFw0zMDA5MTkwODQ2MTFaMIG/MQswCQYDVQQGEwJOTzENMA"
                         + "sGA1UECBMET3NsbzEiMCAGA1UEChMZV29ybGQgV2lkZSBXZWIgQ29uc29ydGl1b"
                         + "TE+MDwGA1UECxM1dzNjLXdpZGdldHMtZGlnc2lnLXRlc3RzdWl0ZSBzZWNvbmQg"
                         + "bGV2ZWwgY2VydGlmaWNhdGUxGzAZBgNVBAMTEmh0dHA6Ly93d3cudzMub3JnLzE"
                         + "gMB4GCSqGSIb3DQEJARYRc3R1YXJ0a0BvcGVyYS5jb20wggEiMA0GCSqGSIb3DQ"
                         + "EBAQUAA4IBDwAwggEKAoIBAQCz8QGhzBdMDXd0qLXY6jEtWudeAAQ5JRsFgV3dd"
                         + "HeU4oeMCnRTDBWtTiwu9NdaZ+nQPwW9j80iG+CQY53HnNjQXeR++xirBREGM4vI"
                         + "vCz/j9qmJ0acoZ6bS4DhOAMVwlk9Ay3UcZlMVjdEHErFSCQ12SXtaX01O60Zh7C"
                         + "EU+Pq6zKYru6/Cdojp+dD+LKZKxAkfsM3aZTw8CVZm/QI8kaNDFfx7OKGVfcATA"
                         + "Rq6WU2HT39icrNgC3Kfxvx2vfv6TA7v+jNcdvRu68mIqWFRGT6RKhHA6HLId26B"
                         + "eXoaTNk+st+cj7nTmCdumhS5eV2nB77G5P207HIYVn4U3ME9xN/AgMBAAGjggF1"
                         + "MIIBcTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQN0Gu0xguc9/fNpplu6LSSir/"
                         + "MdjCB+wYDVR0jBIHzMIHwgBTy0/Kw6ZgHtZ6oV9kRqvRXuOpHuKGBzKSByTCBxj"
                         + "ELMAkGA1UEBhMCTk8xDTALBgNVBAgTBE9zbG8xDTALBgNVBAcTBE9zbG8xIjAgB"
                         + "gNVBAoTGVdvcmxkIFdpZGUgV2ViIENvbnNvcnRpdW0xNjA0BgNVBAsTLXczYy13"
                         + "aWRnZXRzLWRpZ3NpZy10ZXN0c3VpdGUgcm9vdCBjZXJ0aWZpY2F0ZTEbMBkGA1U"
                         + "EAxMSaHR0cDovL3d3dy53My5vcmcvMSAwHgYJKoZIhvcNAQkBFhFzdHVhcnRrQG"
                         + "9wZXJhLmNvbYIJAMTqFP/Wa8uAMEQGCWCGSAGG+EIBDQQ3FjV3M2Mtd2lkZ2V0c"
                         + "y1kaWdzaWctdGVzdHN1aXRlIHNlY29uZCBsZXZlbCBjZXJ0aWZpY2F0ZTANBgkq"
                         + "hkiG9w0BAQUFAAOCAQEAiXxW/08hOf42PasOPSkDbAaR91Dn1JwFSCEvordp7RM"
                         + "9HN0iogjmkkPLXJn2aLgolWQoh4C227JFA9S+dHO8QjiyaVMHcxziIDnfr3+bpG"
                         + "3URpJm1W5T6PJoj0vsB51iUNpwGB75fr2Yt8uGxufsFJDn/Rs78kGkeXmAEKLno"
                         + "Gb7QCrDGcmiEKoqsWvkg3WiYfoK75cgs5bG7xVks7GgSobCohHqmJE96v2EYouM"
                         + "arHnNUVIvn3w2HGxtOiQj4JP9K2nFFx3gxbdgMGXsNyEMh5Kls9H0tQt6QKLMZd"
                         + "127K571k+fJV6mQUtTwOb8jcecFq8PPh/VvNf5cUi1m5P/w==";

        create(write(certStr));
    }

    public static File write(String certStr) throws IOException {
        byte[] ciphertext1 = new BASE64Decoder().decodeBuffer(certStr);
        File f1 = new File("/Users/madding/Downloads/test1.csr");
        FileOutputStream fos1 = new FileOutputStream(f1);
        fos1.write(ciphertext1);
        fos1.flush();
        fos1.close();
        return f1;
    }

    public static void create(File f) throws IOException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream in = new FileInputStream(f);
        Certificate c = cf.generateCertificate(in);
        System.out.println(c);
    }

}
