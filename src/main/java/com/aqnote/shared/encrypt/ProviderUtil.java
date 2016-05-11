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
