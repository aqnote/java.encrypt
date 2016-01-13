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

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.jcajce.provider.digest.SHA224;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.jcajce.provider.digest.SHA384;
import org.bouncycastle.jcajce.provider.digest.SHA512;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.util.ByteUtil;

/**
 * 类SHA.java的实现描述：定义SHA算法相关接口，范围：SHA1 SHA2 serial, SHA3
 * 
 * <pre>
 *  query OID: http://www.oid-info.com/get/2.16.840.1.101.3.4.2.6
 * </pre>
 * 
 * @author madding.lip May 8, 2012 2:01:34 PM
 */
public class SHA {

	private static final String DEFAULT_CHARSET = "UTF-8";

	private static final String OID_SHA1 = OIWObjectIdentifiers.idSHA1.toString();
	private static final String OID_SHA2_224 = NISTObjectIdentifiers.id_sha224.toString();
	private static final String OID_SHA2_256 = NISTObjectIdentifiers.id_sha256.toString();
	private static final String OID_SHA2_384 = NISTObjectIdentifiers.id_sha384.toString();
	private static final String OID_SHA2_512 = NISTObjectIdentifiers.id_sha512.toString();
	private static final String OID_SHA2_512_224 = NISTObjectIdentifiers.id_sha512_224.toString();
	private static final String OID_SHA2_512_256 = NISTObjectIdentifiers.id_sha512_256.toString();

	static {
		ProviderUtil.addBCProvider();
	}

	////// SHA1 ////////////////////////////////////////////////////

	// return 40bit hex
	public final static String sha1(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha1(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 40bit hex
	public final static String sha1(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-1");
			MessageDigest md = MessageDigest.getInstance(OID_SHA1, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 40bit hex
	public final static String _sha1(byte[] src) {
		if (src == null)
			return "";
		SHA1.Digest md = new SHA1.Digest();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	////// SHA2 ////////////////////////////////////////////////////

	// return 56bit hex
	public final static String sha224(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha224(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit hex
	public final static String sha224(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-224",
			// JCE_PROVIDER);
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_224, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit hex
	public final static String _sha224(byte[] src) {
		if (src == null)
			return "";
		SHA224.Digest md = new SHA224.Digest();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 64bit
	public final static String sha256(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha256(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 64bit
	public final static String sha256(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-256",
			// JCE_PROVIDER);
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_256, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 64bit
	public final static String _sha256(byte[] src) {
		if (src == null)
			return "";
		SHA256.Digest md = new SHA256.Digest();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 96bit
	public final static String sha384(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha384(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 96bit
	public final static String sha384(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-384");
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_384, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 96bit
	public final static String _sha384(byte[] src) {
		if (src == null)
			return "";
		SHA384.Digest md = new SHA384.Digest();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 128bit
	public final static String sha512(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha512(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 128bit
	public final static String sha512(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-512");
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_512, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 128bit
	public final static String _sha512(byte[] src) {
		if (src == null)
			return "";
		SHA512.Digest md = new SHA512.Digest();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 56bit
	public final static String sha512_224(String src) {
		if (src == null)
			return "";
		try {
			return sha512_224(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit
	public final static String sha512_224(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-512/256");
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_512_224, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit
	public final static String _sha512_224(byte[] src) {
		if (src == null)
			return "";
		SHA512.DigestT224 md = new SHA512.DigestT224();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 64bit
	public final static String sha512_256(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha512_256(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 64bit
	public final static String sha512_256(byte[] src) {
		if (src == null)
			return "";
		try {
			// MessageDigest md = MessageDigest.getInstance("SHA-512/256");
			MessageDigest md = MessageDigest.getInstance(OID_SHA2_512_256, JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 64bit
	public final static String _sha512_256(byte[] src) {
		if (src == null)
			return "";
		SHA512.DigestT256 md = new SHA512.DigestT256();
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	////// SHA3 ////////////////////////////////////////////////////

	// return 56bit
	public final static String sha3_224(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha3_224(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit
	public final static String sha3_224(byte[] src) {
		if (src == null)
			return "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA3-224", JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 56bit
	public final static String _sha3_224(byte[] src) {
		if (src == null)
			return "";
		DigestSHA3 md = new DigestSHA3(224);
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));

	}

	// return 64bit
	public final static String sha3_256(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha3_256(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	public final static String sha3_256(byte[] src) {
		if (src == null)
			return "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA3-256", JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	public final static String _sha3_256(byte[] src) {
		if (src == null)
			return "";
		DigestSHA3 md = new DigestSHA3(256);
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 96bit
	public final static String sha3_384(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha3_384(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 96bit
	public final static String sha3_384(byte[] src) {
		if (src == null)
			return "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA3-384", JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 96bit
	public final static String _sha3_384(byte[] src) {
		if (src == null)
			return "";
		DigestSHA3 md = new DigestSHA3(384);
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}

	// return 128bit
	public final static String sha3_512(String src) {
		if (isBlank(src))
			return "";
		try {
			return sha3_512(src.getBytes(DEFAULT_CHARSET));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 128bit
	public final static String sha3_512(byte[] src) {
		if (src == null)
			return "";
		try {
			MessageDigest md = MessageDigest.getInstance("SHA3-512", JCE_PROVIDER);
			md.update(src);
			return new String(ByteUtil.toHexBytes(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		return "";
	}

	// return 128bit
	public final static String _sha3_512(byte[] src) {
		if (src == null)
			return "";
		DigestSHA3 md = new DigestSHA3(512);
		md.update(src);
		return new String(ByteUtil.toHexBytes(md.digest()));
	}
}
