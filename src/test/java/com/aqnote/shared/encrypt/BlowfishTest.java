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
package com.aqnote.shared.encrypt;

import org.junit.Assert;

import com.aqnote.shared.encrypt.symmetric.Blowfish;

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
