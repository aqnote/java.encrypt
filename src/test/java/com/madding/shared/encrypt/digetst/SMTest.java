/*
 * Programmer-tools -- A develop code for dever to quickly analyse Copyright (C) 2013-2016 madding.lip
 * <madding.lip@gmail.com>. This library is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation;
 */
package com.madding.shared.encrypt.digetst;

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.StringUtils;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import com.madding.shared.encrypt.digest.SM;

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
