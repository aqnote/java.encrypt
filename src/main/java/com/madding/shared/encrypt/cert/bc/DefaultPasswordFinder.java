package com.madding.shared.encrypt.cert.bc;

import org.bouncycastle.openssl.PasswordFinder;

/**
 * 类DefaultPasswordFinder.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Dec 6, 2013 9:38:42 PM
 */
public class DefaultPasswordFinder implements PasswordFinder {

    public static final char[] PASSWD = "hell01234".toCharArray();

    public char[] getPassword() {
        return PASSWD;
    }

}
