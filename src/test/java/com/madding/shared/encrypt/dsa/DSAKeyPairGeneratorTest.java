/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.dsa;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import com.madding.shared.encrypt.asymmetric.dsa.DSAKeyPairGenTest;

import junit.framework.TestCase;

/**
 * 类DSAKeyPairGeneratorTest.java的实现描述：DSA 私钥和公钥生成器
 * 
 * @author madding.lip May 8, 2012 11:13:43 AM
 */
public class DSAKeyPairGeneratorTest extends TestCase {

    public void test() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        DSAKeyPairGenTest.generator();
    }
}
