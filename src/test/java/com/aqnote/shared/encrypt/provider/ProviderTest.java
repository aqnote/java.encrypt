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
package com.aqnote.shared.encrypt.provider;

import java.security.Provider;
import java.security.Security;
import java.util.Iterator;
import java.util.Set;

import sun.security.pkcs11.SunPKCS11;

/**
 * ProviderOpr.java desc：provider信息查询
 * 
 * @author madding.lip Jun 9, 2014 1:04:08 PM
 */
public class ProviderTest {
    
    static {
        Security.addProvider(new SunPKCS11());
    }

    public static void listProviders() {
        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            printProvider(providers[i]);
        }
    }

    public static void printProvider(Provider provider) {
        if (provider == null) {
            return;
        }
        System.out.println("Provider name: " + provider.getName());
        System.out.println("Provider information: " + provider.getInfo());
        System.out.println("Provider version: " + provider.getVersion());
        Set<?> entries = provider.entrySet();
        Iterator<?> iterator = entries.iterator();
        while (iterator.hasNext()) {
            System.out.println("\tProperty entry: " + iterator.next());
        }
    }

    public static void addProvider(Provider provider) {
        if (provider == null) {
            return;
        }
        Security.addProvider(provider);
    }

    public static void main(String[] args) {
//        printProvider(new SunPKCS11(, "/Library/Java/Home/jre/lib/security/java.security"));
        
//        printProvider(new BouncyCastleProvider());
//        printProvider(new Cryptix());
        
        
        
//        listProviders();
        
        
//        addProvider(new BouncyCastleProvider());
//        addProvider(new Cryptix());
//        listProviders();
    }
}
