/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.asymmetric.dsa;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

import com.madding.shared.encrypt.util.StreamUtil;

/**
 * 类KeyPairGenerator.java的实现描述： DSA方式加密提供私钥和公钥
 * 
 * @author madding.lip May 8, 2012 11:01:01 AM
 */
public class DSAKeyPairGenTest {

    public static final Long   seed      = System.currentTimeMillis();

    public static final String PRIKEY_FILE_NAME;

    public static final String PUBKEY_FILE_NAME;

    public static final String ALGORITHM = "DSA";

    static {
        PRIKEY_FILE_NAME = "/home/madding/" + "my_prikey.dat." + String.valueOf(seed);
        PUBKEY_FILE_NAME = "/home/madding/" + "my_pubkey.dat." + String.valueOf(seed);
    }

    public static void generator() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(ALGORITHM);

        // 如果设定随机产生器就用如相代码初始化
        SecureRandom secrand = new SecureRandom();
        secrand.setSeed(seed); // 初始化随机产生器
        // 初始化密钥生成器, 初始化密钥生成器keysize 算法位长.其范围必须在 512 到 1024 之间，且必须为 64 的倍数
        keygen.initialize(512, secrand);
        // 生成密钥公钥pubkey和私钥prikey
        KeyPair keys = keygen.generateKeyPair(); // 生成密钥组
        PublicKey pubkey = keys.getPublic();
        PrivateKey prikey = keys.getPrivate();
        
        byte[] pubkeyByteArray = Base64.encodeBase64(pubkey.getEncoded());
        OutputStream os = new FileOutputStream(new File(PUBKEY_FILE_NAME));
        ByteArrayInputStream bais = new ByteArrayInputStream(pubkeyByteArray);
        StreamUtil.io(bais, os);
        bais.close();
        os.close();
        
        byte[] prikeyByteArray = Base64.encodeBase64(prikey.getEncoded());
        os = new FileOutputStream(new File(PRIKEY_FILE_NAME));
        bais = new ByteArrayInputStream(prikeyByteArray);
        StreamUtil.io(bais, os);
        bais.close();
        os.close();
    }

}
