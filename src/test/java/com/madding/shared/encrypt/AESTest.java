/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt;

import java.io.UnsupportedEncodingException;

import org.junit.Assert;

import com.madding.shared.encrypt.symmetric.AES;

import junit.framework.TestCase;

/**
 * 类AESTest.java的实现描述：AES算法测试类
 * 
 * @author madding.lip May 8, 2012 1:13:16 PM
 */
public class AESTest extends TestCase {

    public void test() throws UnsupportedEncodingException, RuntimeException {
        Assert.assertEquals("8c08156ddee73404ecada83f81d3a4e4", AES.encrypt("testlip"));
        Assert.assertEquals(AES.decrypt("8c08156ddee73404ecada83f81d3a4e4"), "testlip");
    }
}
