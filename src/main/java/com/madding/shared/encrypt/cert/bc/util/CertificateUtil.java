package com.madding.shared.encrypt.cert.bc.util;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * 类CertUtil.java的实现描述：证书操作工具类
 * 
 * @author madding.lip Nov 19, 2013 7:37:00 PM
 */
public class CertificateUtil {
    
    public static String getValue(RDN rdn) {
        if(rdn == null) return null;
        return IETFUtils.valueToString(rdn.getFirst().getValue());
    }
    
    public static X500Name getSubject(X509Certificate cert) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(cert).getSubject();
    }
    
    public static X500Name getIssuer(X509Certificate cert) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(cert).getIssuer();
    }

    public static String getSubjectEmail(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        return getValue(x500name.getRDNs(BCStyle.E)[0]);
    }

    public static String getSubjectCN(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        return getValue(x500name.getRDNs(BCStyle.CN)[0]);
    }

    public static String getSubjectTitle(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        return getValue(x500name.getRDNs(BCStyle.T)[0]);
    }

    public static String getIssuerEmail(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getIssuer();
        return getValue(x500name.getRDNs(BCStyle.E)[0]);
    }

    public static String getIssuerCN(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getIssuer();
        return getValue(x500name.getRDNs(BCStyle.CN)[0]);
    }

    public static String getIssuerTitle(X509Certificate cert) throws CertificateEncodingException {
        if (cert == null) return null;
        X500Name x500name = new JcaX509CertificateHolder(cert).getIssuer();
        return getValue(x500name.getRDNs(BCStyle.T)[0]);
    }

}
