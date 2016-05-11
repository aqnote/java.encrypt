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
package com.aqnote.shared.encrypt.cert.bc;

import org.bouncycastle.openssl.PasswordFinder;

/**
 * 类CAPasswordFinder.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 9:38:42 PM
 */
public class CAPasswordFinder implements PasswordFinder {

    public static final char[] PASSWD = "12345".toCharArray();

    public char[] getPassword() {
        return PASSWD;
    }

}
