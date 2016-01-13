package com.madding.shared.encrypt.cert.bc.main;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.constant.MadDateConstant;
import com.madding.shared.encrypt.cert.bc.cover.MadPKCSWriter;
import com.madding.shared.encrypt.cert.bc.loader.MadCaCertLoader;
import com.madding.shared.encrypt.cert.bc.util.X500NameUtil;
import com.madding.shared.encrypt.cert.exception.MadCertException;

/**
 * 类CRLOpCreator.java的实现描述：证书吊销列表构造类
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class MadCRLCreator implements MadBCConstant {

    public static String MAD_CRL_FILE = "/home/madding/output/mad.crl";

    public static void main(String[] args) throws MadCertException {
        createNewCRL();
    }

    public static void createNewCRL() throws MadCertException {

        try {
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(X500NameUtil.createRootPrincipal(), new Date());
            crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + MadDateConstant.ONE_YEAR));
            X509CRLHolder crlHolder = crlBuilder.build(new JcaContentSignerBuilder(SHA256_RSA).setProvider(JCE_PROVIDER).build(MadCaCertLoader.getCaKeyPair().getPrivate()));
            X509CRL crl = new JcaX509CRLConverter().setProvider(JCE_PROVIDER).getCRL(crlHolder);
            FileOutputStream fostream = new FileOutputStream(MAD_CRL_FILE);
            MadPKCSWriter.storeCRLFile(crl, fostream);

            ASN1Dump.dumpAsString(crlHolder.toASN1Structure());
        } catch (OperatorCreationException e) {
            throw new MadCertException(e);
        } catch (IOException e) {
            throw new MadCertException(e);
        } catch (InvalidKeyException e) {
            throw new MadCertException(e);
        } catch (CRLException e) {
            throw new MadCertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new MadCertException(e);
        } catch (NoSuchProviderException e) {
            throw new MadCertException(e);
        } catch (SignatureException e) {
            throw new MadCertException(e);
        } catch (Exception e) {
            throw new MadCertException(e);
        }

        return;
    }
}
