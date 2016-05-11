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
package com.aqnote.shared.encrypt.digetst;

import junit.framework.TestCase;

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.StringUtils;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import com.aqnote.shared.encrypt.digest.SHA;

/**
 * SHATest.java desc：TODO
 * 
 * @author madding.lip Dec 23, 2015 4:38:43 PM
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SHATest extends TestCase {

    public void test00_basic() {
        // SHA1
        System.out.println(SHA.sha1("13675815985")); // 40bit
        
        // SHA2
        System.out.println(SHA.sha224("13675815985")); // 56bit BC
        System.out.println(SHA.sha256("13675815985")); // 64bit BC
        System.out.println(SHA.sha384("13675815985")); // 96bit
        System.out.println(SHA.sha512("13675815985")); // 128bit
        System.out.println(SHA.sha512_224("13675815985")); // 56bit
        System.out.println(SHA.sha512_256("13675815985")); // 64bit

        // SHA3
        System.out.println(SHA.sha3_224("13675815985")); // 56bit BC
        System.out.println(SHA.sha3_256("13675815985")); // 64bit BC
        System.out.println(SHA.sha3_384("13675815985")); // 96bit BC
        System.out.println(SHA.sha3_512("13675815985")); // 128bit BC

    }

    public void test01_param_null() {
        String src = null;
        byte[] src2 = null;
        SHA.sha1(src);
        SHA.sha1(src2);
        SHA._sha1(src2);
        SHA.sha224(src);
        SHA.sha224(src2);
        SHA._sha224(src2);
        SHA.sha256(src);
        SHA.sha256(src2);
        SHA._sha256(src2);
        SHA.sha384(src);
        SHA.sha384(src2);
        SHA._sha384(src2);
        SHA.sha512(src);
        SHA.sha512(src2);
        SHA._sha512(src2);
        SHA.sha512_224(src);
        SHA.sha512_224(src2);
        SHA._sha512_224(src2);
        SHA.sha512_256(src);
        SHA.sha512_256(src2);
        SHA._sha512_224(src2);
        SHA.sha3_224(src);
        SHA.sha3_224(src2);
        SHA._sha3_224(src2);
        SHA.sha3_256(src);
        SHA.sha3_256(src2);
        SHA._sha3_224(src2);
        SHA.sha3_384(src);
        SHA.sha3_384(src2);
        SHA._sha3_256(src2);
        SHA.sha3_512(src);
        SHA.sha3_512(src2);
        SHA._sha3_512(src2);
    }
    
    public void test02_innerMethod() throws UnsupportedEncodingException {
        // SHA1
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha1("13675815985"), SHA._sha1("13675815985".getBytes("UTF-8"))));
        
        // SHA2
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha224("13675815985"), SHA._sha224("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha256("13675815985"), SHA._sha256("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha384("13675815985"), SHA._sha384("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha512("13675815985"), SHA._sha512("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha512_224("13675815985"), SHA._sha512_224("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha512_256("13675815985"), SHA._sha512_256("13675815985".getBytes("UTF-8"))));

        // SHA3
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha3_224("13675815985"), SHA._sha3_224("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha3_256("13675815985"), SHA._sha3_256("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha3_384("13675815985"), SHA._sha3_384("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SHA.sha3_512("13675815985"), SHA._sha3_512("13675815985".getBytes("UTF-8"))));
    }
}
