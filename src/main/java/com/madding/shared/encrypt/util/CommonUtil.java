package com.madding.shared.encrypt.util;

import java.util.Random;

import org.apache.commons.lang.StringUtils;

/**
 * 类Util.java的实现描述：TODO 类实现描述
 * 
 * @author madding.lip Nov 18, 2013 12:26:27 AM
 */
public class CommonUtil {

    private static char[] ASCII_CHAR = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
            'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

    public static String ArrayToString(String[] arrays, char sep) {
        String macStr = "";
        for (String b : arrays) {
            if (StringUtils.isBlank(macStr)) {
                macStr = macStr + b;
            } else {
                macStr = macStr + sep + b;
            }
        }
        return macStr;
    }

    public static String mergeString(String... strs) {
        StringBuilder sb = new StringBuilder();
        for (String str : strs) {
            sb.append(str);
        }
        return sb.toString();
    }

    public static String genRandom(int length) {
        final int maxNum = ASCII_CHAR.length;
        int i;
        int count = 0;

        Random r = new Random();
        StringBuffer pwd = new StringBuffer("");
        while (count++ < length) {
            i = Math.abs(r.nextInt(maxNum));
            if (i >= 0 && i < ASCII_CHAR.length) {
                pwd.append(ASCII_CHAR[i]);
            }
        }
        return pwd.toString();
    }
}
