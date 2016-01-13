/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt;

import org.junit.Assert;

import com.madding.shared.encrypt.symmetric.Blowfish;

import junit.framework.TestCase;

/**
 * 类BlowfishTest.java的实现描述：blowfish测试
 * 
 * @author madding.lip May 8, 2012 2:18:16 PM
 */
public class BlowfishTest extends TestCase {

    protected void setUp() throws Exception {
        
    }

    public void testEncrypt() {
        System.out.println(Blowfish.encrypt("abasd中文1234!@#$"));
        Assert.assertEquals("lo5S3AFpCSZKMYp1Z0giL8z8n4j2Hw4f", Blowfish.encrypt("abasd中文1234!@#$"));
    }

    public void testDecrypt() {
        System.out.println(Blowfish.decrypt("lo5S3AFpCSZKMYp1Z0giL8z8n4j2Hw4f"));
        Assert.assertEquals("abasd中文1234!@#$", Blowfish.decrypt("lo5S3AFpCSZKMYp1Z0giL8z8n4j2Hw4f"));
    }
}
