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

import java.io.UnsupportedEncodingException;

import org.junit.Assert;

import com.aqnote.shared.encrypt.symmetric.AES;

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
