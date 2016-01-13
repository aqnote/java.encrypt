/*
 * Copyright madding.me.
 */
package com.madding.shared.encrypt.digest;

import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.JCE_PROVIDER;
import static org.apache.commons.lang.StringUtils.isBlank;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.digest.MD2;
import org.bouncycastle.jcajce.provider.digest.MD4;
import org.bouncycastle.jcajce.provider.digest.MD5;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.util.ByteUtil;

/**
 * 类Md5.java的实现描述：TODO 类实现描述 query OID: http://www.oid-info.com/get/2.16.840.1.101.3.4.2.6
 * 
 * @author madding.lip May 8, 2012 1:59:09 PM
 */
public class MD {

    private static final String DEFAULT_CHARSET = "UTF-8";

    private static final String OID_MD2         = PKCSObjectIdentifiers.md2.toString();
    private static final String OID_MD4         = PKCSObjectIdentifiers.md4.toString();
    private static final String OID_MD5         = PKCSObjectIdentifiers.md5.toString();

    static {
        ProviderUtil.addBCProvider();
    }

    public final static String md2(String src) {
        if (isBlank(src)) return "";
        try {
            return md2(src.getBytes(DEFAULT_CHARSET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String md2(byte[] src) {
        if (src == null) return "";
        try {
            // MessageDigest messageDigest = MessageDigest.getInstance("MD2");
            MessageDigest messageDigest = MessageDigest.getInstance(OID_MD2, JCE_PROVIDER);
            messageDigest.update(src);
            return new String(ByteUtil.toHexBytes(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String _md2(byte[] src) {
        if (src == null) return "";
        MD2.Digest md = new MD2.Digest();
        md.update(src);
        return new String(ByteUtil.toHexBytes(md.digest()));
    }

    public final static String md4(String src) {
        if (isBlank(src)) return "";
        try {
            return md4(src.getBytes(DEFAULT_CHARSET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String md4(byte[] src) {
        if (src == null) return "";
        try {
            // MessageDigest messageDigest = MessageDigest.getInstance("MD4");
            MessageDigest messageDigest = MessageDigest.getInstance(OID_MD4, JCE_PROVIDER);
            messageDigest.update(src);
            return new String(ByteUtil.toHexBytes(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String _md4(byte[] src) {
        if (src == null) return "";
        MD4.Digest md = new MD4.Digest();
        md.update(src);
        return new String(ByteUtil.toHexBytes(md.digest()));
    }

    public final static String md5(String src) {
        if (isBlank(src)) return "";
        try {
            return md5(src.getBytes(DEFAULT_CHARSET));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String md5(byte[] src) {
        if (src == null) return "";
        try {
            // MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            MessageDigest messageDigest = MessageDigest.getInstance(OID_MD5, JCE_PROVIDER);

            messageDigest.update(src);
            return new String(ByteUtil.toHexBytes(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String _md5(byte[] src) {
        if (src == null) return "";
        MD5.Digest md = new MD5.Digest();
        return new String(ByteUtil.toHexBytes(md.digest()));
    }

}
