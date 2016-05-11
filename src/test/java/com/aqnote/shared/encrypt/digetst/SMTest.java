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

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.StringUtils;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import com.aqnote.shared.encrypt.digest.SM;

import junit.framework.TestCase;

/**
 * SMTest.java desc：TODO
 * 
 * @author madding.lip Dec 24, 2015 6:19:59 PM
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SMTest extends TestCase {

    public void test01() throws UnsupportedEncodingException {
        System.out.println(SM.sm3("13675815986")); // 64bit
        System.out.println(SM._sm3("13675815985".getBytes("UTF-8"))); // 64bit

        Assert.assertTrue(StringUtils.equalsIgnoreCase(SM.sm3("13675815985".getBytes("UTF-8")),
                                                       SM._sm3("13675815985".getBytes("UTF-8"))));
        Assert.assertTrue(StringUtils.equalsIgnoreCase(SM.sm3("13675815985"),
                                                       SM._sm3("13675815985".getBytes("UTF-8"))));
    }
}
