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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.commons.lang.StringUtils;

import com.aqnote.shared.encrypt.asymmetric.dsa.DSA;
import com.aqnote.shared.encrypt.util.StreamUtil;

import junit.framework.TestCase;

/**
 * 类DASTest.java的实现描述：DSA测试类
 * 
 * @author madding.lip May 8, 2012 9:15:11 AM
 */
public class DSATest extends TestCase {

    DSA dsa;

    protected void setUp() throws Exception {
        dsa = new DSA();
        initDSA(null);
    }

    public void test() {
        String context = "{username:madding, password:madding, sign:1234563298}";
        String dsaContext = dsa.sign(context, "hello");
        System.out.println(dsaContext);
        dsa.verify(context, dsaContext, "hello");
    }

    private void initDSA(String keyPairName) throws Exception {
        if (StringUtils.isEmpty(keyPairName)) {
            keyPairName = "hello";
        }
        InputStream istream = new FileInputStream(new File("src/test/resources/dsa/" + keyPairName + "_prikey.dat"));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        StreamUtil.io(istream, baos);
        byte[] priKeyBytes = baos.toByteArray();
        dsa.setPrivateKey("hello", priKeyBytes);
        istream.close();
        baos.close();

        istream = new FileInputStream(new File("src/test/resources/dsa/" + keyPairName + "_pubkey.dat"));
        baos = new ByteArrayOutputStream();
        StreamUtil.io(istream, baos);
        byte[] pubKeyBytes = baos.toByteArray();
        dsa.setPublicKey("hello", pubKeyBytes);
        istream.close();
        baos.close();
    }
}
