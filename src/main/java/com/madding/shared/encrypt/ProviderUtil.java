/*
 * Programmer-tools -- A develop code for dever to quickly analyse
 * Copyright (C) 2013-2016 madding.lip <madding.lip@gmail.com>.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation;
 */
package com.madding.shared.encrypt;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Provider.java desc：TODO 
 * @author madding.lip Dec 23, 2015 5:42:52 PM
 */
public class ProviderUtil {
    
    public static void addBCProvider() {
        Provider bcProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if(bcProvider == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
