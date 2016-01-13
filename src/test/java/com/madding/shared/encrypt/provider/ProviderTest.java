/*
 * Programmer-tools -- A develop code for dever to quickly analyse Copyright (C) 2013-2016 madding.lip
 * <madding.lip@gmail.com>. This library is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation;
 */
package com.madding.shared.encrypt.provider;

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
