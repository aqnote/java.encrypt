/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt;

import org.junit.Assert;

import com.madding.shared.encrypt.symmetric.DES;

import junit.framework.TestCase;

/**
 * 类DesEncryptTest.java的实现描述：DESEncrypt单元测试类
 * 
 * @author madding.lip May 7, 2012 3:04:12 PM
 */
public class DESTest extends TestCase {

    public void testDESEncrypt() {
        System.out.println(DES.encrypt("testlip"));
        Assert.assertEquals("d8d6ec9dee9c7f8b", DES.encrypt("testlip"));
    }
}
