package com.madding.shared.encrypt.cert.bc;

import org.bouncycastle.openssl.PasswordFinder;

/**
 * 类UserPasswordFinder.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 9:38:42 PM
 */
public class UserPasswordFinder implements PasswordFinder {

    public static final char[] PASSWD = "12345".toCharArray();

    public char[] getPassword() {
        return PASSWD;
    }

}
