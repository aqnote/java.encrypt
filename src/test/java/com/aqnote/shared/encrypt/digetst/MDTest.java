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

import com.aqnote.shared.encrypt.digest.MD;

import junit.framework.TestCase;

/**
 * 类MD5Test.java的实现描述：TODO 类实现描述 
 * @author madding.lip May 8, 2012 4:13:04 PM
 */
public class MDTest extends TestCase {

    public void test() {
        System.out.println(MD.md2("13675815985"));  // 32bit
        System.out.println(MD.md4("13675815985"));  // 32bit
        System.out.println(MD.md5("13675815985"));  // 32bit
    }
}
