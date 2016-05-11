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

import com.aqnote.shared.encrypt.symmetric.DES;

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
