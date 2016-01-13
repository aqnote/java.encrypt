/*
 * Programmer-tools -- A develop code for dever to quickly analyse Copyright (C) 2013-2016 madding.lip
 * <madding.lip@gmail.com>. This library is free software; you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation;
 */
package com.madding.shared.encrypt.util;

import java.io.IOException;
import java.net.URL;
import java.security.cert.Certificate;

import javax.net.ssl.HttpsURLConnection;

/**
 * CertUtil.java desc：get server certificate util
 * 
 * @author madding.lip May 12, 2014 10:09:15 AM
 */
public class CertUtil {

    public static Certificate[] getServerCertList(URL url) {
        HttpsURLConnection connection;
        try {
            connection = (HttpsURLConnection) url.openConnection();
            connection.connect();
            Certificate[] certs = connection.getServerCertificates();
            return certs;
        } catch (IOException e) {
            System.err.println(e);
        }
        return null;
    }
}
