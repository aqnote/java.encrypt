package com.madding.shared.encrypt.cert.self.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

/**
 * 类KeyStoreFileTool.java的实现描述：私钥处理类
 * 
 * @author madding.lip Nov 18, 2013 12:01:35 PM
 */
public class KeyStoreFileUtil {

    public static void writePkcsFile(String b64P12, String p12fileName) throws IOException {
        
        if (StringUtils.isBlank(p12fileName) || StringUtils.isBlank(b64P12)) {
            return;
        }
        byte[] p12File = Base64.decodeBase64(b64P12);
        FileOutputStream fos = new FileOutputStream(p12fileName);
        fos.write(p12File);
        fos.flush();
        fos.close();
    }

    /**
     * 读取KeyStore里面的私钥（字符串形式）
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static String readPrivateKeyStr(String alias, String pfxPath, String password)
                                                                                         throws UnrecoverableKeyException,
                                                                                         KeyStoreException,
                                                                                         NoSuchAlgorithmException,
                                                                                         CertificateException,
                                                                                         IOException {

        PrivateKey privateKey = readPrivateKey(alias, pfxPath, password);

        return privateKey.toString().replace(" ", "");

    }

    /**
     * 根据KeyStore读取模数N
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getModulusByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("modulus:") + "modulus:".length(), pfx.indexOf("publicexponent:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取公钥e
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getPubExponentByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("publicexponent:") + "publicexponent:".length(),
                                       pfx.indexOf("privateexponent:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取私钥d
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getPriExponentByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("privateexponent:") + "privateexponent:".length(),
                                       pfx.indexOf("primep:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取p
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getpByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("primep:") + "primep:".length(), pfx.indexOf("primeq:"));

        return modulus.trim().replace(" ", "");
    }

    /**
     * 根据KeyStore读取q
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getqByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("primeq:") + "primeq:".length(), pfx.indexOf("primeexponentp:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取dp
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getdpByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("primeexponentp:") + "primeexponentp:".length(),
                                       pfx.indexOf("primeexponentq:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取dq
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getdqByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("primeexponentq:") + "primeexponentq:".length(),
                                       pfx.indexOf("crtcoefficient:"));

        return modulus.trim().replace(" ", "");

    }

    /**
     * 根据KeyStore读取qInv
     * 
     * @param alias
     * @param pfxPath
     * @param password
     * @return
     */
    public static String getqInvByPfx(String alias, String pfxPath, String password) {

        String pfx = "";
        try {
            pfx = readPrivateKeyStr(alias, pfxPath, password);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        String modulus = pfx.substring(pfx.indexOf("crtcoefficient:") + "crtcoefficient:".length(), pfx.length());

        return modulus.trim().replace(" ", "");

    }

    /**
     * 读取PFX文件中的私钥
     * 
     * @param alias 别名
     * @param pfxPath PFX文件路径
     * @param password 密码
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws UnrecoverableKeyException
     */
    public static PrivateKey readPrivateKey(String alias, String pfxPath, String password) throws KeyStoreException,
                                                                                          NoSuchAlgorithmException,
                                                                                          CertificateException,
                                                                                          IOException,
                                                                                          UnrecoverableKeyException {

        KeyStore keyStore = KeyStore.getInstance("pkcs12");

        FileInputStream fis = null;

        fis = new FileInputStream(pfxPath);

        keyStore.load(fis, password.toCharArray());

        fis.close();

        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

}
