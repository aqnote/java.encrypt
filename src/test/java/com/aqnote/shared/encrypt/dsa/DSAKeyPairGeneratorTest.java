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
package com.aqnote.shared.encrypt.dsa;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import com.aqnote.shared.encrypt.asymmetric.dsa.DSAKeyPairGenTest;

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
