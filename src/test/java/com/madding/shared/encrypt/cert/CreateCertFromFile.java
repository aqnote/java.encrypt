package com.madding.shared.encrypt.cert;

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

//    public static void main(String[] args) throws IOException, CertificateException {
//
//        String certStr = "MIIFeTCCBGGgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBxjELMAkGA1UEBhMCTk8xDTALBgNVBAgTBE9zbG8xDTALBgNVBAcTBE9zbG8xIjAgBgNVBAoTGVdvcmxkIFdpZGUgV2ViIENvbnNvcnRpdW0xNjA0BgNVBAsTLXczYy13aWRnZXRzLWRpZ3NpZy10ZXN0c3VpdGUgcm9vdCBjZXJ0aWZpY2F0ZTEbMBkGA1UEAxMSaHR0cDovL3d3dy53My5vcmcvMSAwHgYJKoZIhvcNAQkBFhFzdHVhcnRrQG9wZXJhLmNvbTAeFw0xMDA5MjQwODQ2MTFaFw0zMDA5MTkwODQ2MTFaMIG/MQswCQYDVQQGEwJOTzENMAsGA1UECBMET3NsbzEiMCAGA1UEChMZV29ybGQgV2lkZSBXZWIgQ29uc29ydGl1bTE+MDwGA1UECxM1dzNjLXdpZGdldHMtZGlnc2lnLXRlc3RzdWl0ZSBzZWNvbmQgbGV2ZWwgY2VydGlmaWNhdGUxGzAZBgNVBAMTEmh0dHA6Ly93d3cudzMub3JnLzEgMB4GCSqGSIb3DQEJARYRc3R1YXJ0a0BvcGVyYS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz8QGhzBdMDXd0qLXY6jEtWudeAAQ5JRsFgV3ddHeU4oeMCnRTDBWtTiwu9NdaZ+nQPwW9j80iG+CQY53HnNjQXeR++xirBREGM4vIvCz/j9qmJ0acoZ6bS4DhOAMVwlk9Ay3UcZlMVjdEHErFSCQ12SXtaX01O60Zh7CEU+Pq6zKYru6/Cdojp+dD+LKZKxAkfsM3aZTw8CVZm/QI8kaNDFfx7OKGVfcATARq6WU2HT39icrNgC3Kfxvx2vfv6TA7v+jNcdvRu68mIqWFRGT6RKhHA6HLId26BeXoaTNk+st+cj7nTmCdumhS5eV2nB77G5P207HIYVn4U3ME9xN/AgMBAAGjggF1MIIBcTAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBQN0Gu0xguc9/fNpplu6LSSir/MdjCB+wYDVR0jBIHzMIHwgBTy0/Kw6ZgHtZ6oV9kRqvRXuOpHuKGBzKSByTCBxjELMAkGA1UEBhMCTk8xDTALBgNVBAgTBE9zbG8xDTALBgNVBAcTBE9zbG8xIjAgBgNVBAoTGVdvcmxkIFdpZGUgV2ViIENvbnNvcnRpdW0xNjA0BgNVBAsTLXczYy13aWRnZXRzLWRpZ3NpZy10ZXN0c3VpdGUgcm9vdCBjZXJ0aWZpY2F0ZTEbMBkGA1UEAxMSaHR0cDovL3d3dy53My5vcmcvMSAwHgYJKoZIhvcNAQkBFhFzdHVhcnRrQG9wZXJhLmNvbYIJAMTqFP/Wa8uAMEQGCWCGSAGG+EIBDQQ3FjV3M2Mtd2lkZ2V0cy1kaWdzaWctdGVzdHN1aXRlIHNlY29uZCBsZXZlbCBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQUFAAOCAQEAiXxW/08hOf42PasOPSkDbAaR91Dn1JwFSCEvordp7RM9HN0iogjmkkPLXJn2aLgolWQoh4C227JFA9S+dHO8QjiyaVMHcxziIDnfr3+bpG3URpJm1W5T6PJoj0vsB51iUNpwGB75fr2Yt8uGxufsFJDn/Rs78kGkeXmAEKLnoGb7QCrDGcmiEKoqsWvkg3WiYfoK75cgs5bG7xVks7GgSobCohHqmJE96v2EYouMarHnNUVIvn3w2HGxtOiQj4JP9K2nFFx3gxbdgMGXsNyEMh5Kls9H0tQt6QKLMZd127K571k+fJV6mQUtTwOb8jcecFq8PPh/VvNf5cUi1m5P/w==";
//        
//        create(write(certStr));
//    }
//    
//    public static File write(String certStr) throws IOException {
//        byte[] ciphertext1 = new BASE64Decoder().decodeBuffer(certStr);
//        File f1 = new File("/home/madding/output/test1.csr");
//        FileOutputStream fos1 = new FileOutputStream(f1);
//        fos1.write(ciphertext1);
//        fos1.flush();
//        fos1.close();
//        return f1;
//    }
//
//    public static void create(File f) throws IOException, CertificateException {
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        FileInputStream in = new FileInputStream(f);
//        Certificate c = cf.generateCertificate(in);
//    }

}
