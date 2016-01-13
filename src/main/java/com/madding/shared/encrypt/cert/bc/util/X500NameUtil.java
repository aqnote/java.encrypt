package com.madding.shared.encrypt.cert.bc.util;

import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * 类X509PrincipalUtil.java的实现描述：x509规则构造类
 * 
 * @author madding.lip Dec 5, 2013 4:39:19 PM
 */
public class X500NameUtil {

    public static final String DN_C              = "CN";
    public static final String DN_ST             = "ZheJiang";
    public static final String DN_L              = "HangZhou";
    public static final String DN_O              = "Mad";
    public static final String DN_OU             = "Inc";

    public static final String DN_ROOT_O         = "Mad Software Co., Ltd";
    public static final String DN_ROOT_OU        = "http://www.aqnote.com";
    public static final String DN_ROOT_CN        = "Mad Cert Signing Authority";
    public static final String DN_ROOT_E         = "madding.lip@gmail.com";

    public static final String DN_MASTER_CN      = "Mad CA";

    public static final String DN_CLASS1_ROOT_CN = "Mad Class 1 Root";

    public static final String DN_CLASS2_ROOT_CN = "Mad class 2 Root";

    public static final String DN_CLASS3_ROOT_CN = "Mad Class 3 Root";
    public static final String DN_CLASS3_END_OU  = "staffengineer";

    public static final String DN_E_ROOT         = "madding.lip@gmail.com";

    /** madding根证书构造 */
    public static X500Name createRootPrincipal() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.E, DN_ROOT_E);
        x500NameBuilder.addRDN(BCStyle.CN, DN_ROOT_CN);
        x500NameBuilder.addRDN(BCStyle.OU, DN_ROOT_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_ROOT_O);
        return x500NameBuilder.build();
    }

    public static X500Name createClass1RootPrincipal() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, DN_CLASS1_ROOT_CN);
        x500NameBuilder.addRDN(BCStyle.OU, DN_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_O);
        return x500NameBuilder.build();
    }

    public static X500Name createClass1EndPrincipal(String cn, String email) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.E, email);
        x500NameBuilder.addRDN(BCStyle.CN, cn);
        x500NameBuilder.addRDN(BCStyle.OU, DN_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_O);
        x500NameBuilder.addRDN(BCStyle.L, DN_L);
        x500NameBuilder.addRDN(BCStyle.ST, DN_ST);
        x500NameBuilder.addRDN(BCStyle.C, DN_C);
        return x500NameBuilder.build();
    }

    public static X500Name createClass3RootPrincipal() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.CN, DN_CLASS3_ROOT_CN);
        x500NameBuilder.addRDN(BCStyle.OU, DN_ROOT_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_ROOT_O);
        return x500NameBuilder.build();
    }

    public static X500Name createClass3EndPrincipal(String cn, String email, String title) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.E, email);
        x500NameBuilder.addRDN(BCStyle.CN, cn);
        x500NameBuilder.addRDN(BCStyle.T, title);
        x500NameBuilder.addRDN(BCStyle.OU, DN_CLASS3_END_OU);
//        x500NameBuilder.addRDN(BCStyle.O, DN_O);
//        x500NameBuilder.addRDN(BCStyle.L, DN_L);
//        x500NameBuilder.addRDN(BCStyle.ST, DN_ST);
//        x500NameBuilder.addRDN(BCStyle.C, DN_C);
        return x500NameBuilder.build();
    }

    public static X500Name createClass3EndPrincipal(String cn, String email) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.E, email);
        x500NameBuilder.addRDN(BCStyle.CN, cn);
        x500NameBuilder.addRDN(BCStyle.OU, DN_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_O);
        x500NameBuilder.addRDN(BCStyle.L, DN_L);
        x500NameBuilder.addRDN(BCStyle.ST, DN_ST);
        x500NameBuilder.addRDN(BCStyle.C, DN_C);
        return x500NameBuilder.build();
    }

    public static X500Name createClass3EndPrincipal(List<String> cnList, String email) {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBuilder.addRDN(BCStyle.E, email);
        for (String cn : cnList) {
            x500NameBuilder.addRDN(BCStyle.CN, cn);
        }
        x500NameBuilder.addRDN(BCStyle.OU, DN_OU);
        x500NameBuilder.addRDN(BCStyle.O, DN_O);
        x500NameBuilder.addRDN(BCStyle.L, DN_L);
        x500NameBuilder.addRDN(BCStyle.ST, DN_ST);
        x500NameBuilder.addRDN(BCStyle.C, DN_C);
        return x500NameBuilder.build();
    }

}
