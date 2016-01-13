package com.madding.shared.encrypt.cert.gen;

import static com.madding.shared.encrypt.cert.bc.constant.MadCertConstant.MAD_CRL_URL;
import static com.madding.shared.encrypt.cert.bc.constant.MadDateConstant.FIVE_YEAR;
import static com.madding.shared.encrypt.cert.bc.constant.MadDateConstant.HALF_DAY;
import static com.madding.shared.encrypt.cert.bc.constant.MadDateConstant.ONE_DAY;
import static com.madding.shared.encrypt.cert.bc.constant.MadDateConstant.TWENTY_YEAR;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.madding.shared.encrypt.ProviderUtil;
import com.madding.shared.encrypt.cert.bc.constant.MadBCConstant;
import com.madding.shared.encrypt.cert.bc.constant.MadCertConstant;
import com.madding.shared.encrypt.cert.bc.constant.MadDateConstant;
import com.madding.shared.encrypt.cert.bc.util.CertificateUtil;
import com.madding.shared.encrypt.cert.bc.util.X500NameUtil;

/**
 * 证书创建工厂,用于处理证书的创建工作
 * 
 * @author madding.lip
 */
public class BCCertGenerator implements MadBCConstant {

    private static ThreadLocal<BCCertGenerator> threadlocal     = new ThreadLocal<BCCertGenerator>();

    protected static final KeyPurposeId[]       BASE_EKU        = new KeyPurposeId[2];
    protected static final KeyPurposeId[]       MOST_EKU        = new KeyPurposeId[5];

    protected static int                        WHOLE_KEY_USAGE = KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                                                                  | KeyUsage.keyEncipherment
                                                                  | KeyUsage.dataEncipherment | KeyUsage.keyAgreement
                                                                  | KeyUsage.keyCertSign | KeyUsage.cRLSign
                                                                  | KeyUsage.encipherOnly | KeyUsage.decipherOnly;

    protected static int                        END_KEY_USAGE   = KeyUsage.digitalSignature | KeyUsage.keyEncipherment;

    static {
        ProviderUtil.addBCProvider();

        BASE_EKU[0] = KeyPurposeId.id_kp_clientAuth;
        BASE_EKU[1] = KeyPurposeId.id_kp_serverAuth;

        MOST_EKU[0] = KeyPurposeId.id_kp_clientAuth;
        MOST_EKU[1] = KeyPurposeId.id_kp_serverAuth;

        MOST_EKU[2] = KeyPurposeId.id_kp_eapOverPPP;
        MOST_EKU[3] = KeyPurposeId.id_kp_eapOverLAN;

        MOST_EKU[4] = KeyPurposeId.id_kp_ipsecIKE;
        // MOST_EKU[5] = KeyPurposeId.id_kp_ipsecUser;
        // MOST_EKU[6] = KeyPurposeId.id_kp_ipsecTunnel;
        // MOST_EKU[7] = KeyPurposeId.id_kp_ipsecEndSystem;

    }

    public static BCCertGenerator getIns() {
        if (threadlocal.get() == null) {
            threadlocal.set(new BCCertGenerator());
        }
        return threadlocal.get();
    }

    public X509Certificate createRootCaCert(final KeyPair keyPair) throws Exception {

        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();

        X500Name idn = X500NameUtil.createRootPrincipal();
        BigInteger sno = BigInteger.valueOf(1);
        Date nb = new Date(System.currentTimeMillis() - ONE_DAY);
        Date na = new Date(nb.getTime() + TWENTY_YEAR);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(idn, sno, nb, na, idn, pubKey);

        addSubjectKID(certBuilder, pubKey);
        addAuthorityKID(certBuilder, pubKey);
        addCRLDistributionPoints(certBuilder);
        addAuthorityInfoAccess(certBuilder);
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Boolean.TRUE));

        X509Certificate certificate = signCert(certBuilder, privKey);
        certificate.checkValidity(new Date());
        certificate.verify(pubKey);

        setPKCS9Info(certificate);

        return certificate;
    }

    public X509Certificate createClass3RootCert(KeyPair keyPair, PrivateKey ppk, X509Certificate caCert)
                                                                                                        throws Exception {

        X500Name idn = CertificateUtil.getSubject(caCert);
        BigInteger sno = BigInteger.valueOf(5);
        Date nb = new Date(System.currentTimeMillis() - HALF_DAY);
        Date na = new Date(nb.getTime() + TWENTY_YEAR);
        X500Name sdn = X500NameUtil.createClass3RootPrincipal();
        PublicKey pubKey = keyPair.getPublic();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(idn, sno, nb, na, sdn, pubKey);

        addSubjectKID(certBuilder, pubKey);
        addAuthorityKID(certBuilder, caCert.getPublicKey());
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Boolean.TRUE));

        X509Certificate certificate = signCert(certBuilder, ppk);
        certificate.checkValidity(new Date());
        certificate.verify(caCert.getPublicKey());

        setPKCS9Info(certificate);

        return certificate;
    }

    public X509Certificate createClass1CaCert(KeyPair keyPair, PrivateKey ppk, X509Certificate caCert) throws Exception {

        X500Name idn = CertificateUtil.getSubject(caCert);
        BigInteger sno = BigInteger.valueOf(3);
        Date nb = new Date(System.currentTimeMillis() - HALF_DAY);
        Date na = new Date(nb.getTime() + TWENTY_YEAR);
        X500Name sdn = X500NameUtil.createClass1RootPrincipal();
        PublicKey pubKey = keyPair.getPublic();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(idn, sno, nb, na, sdn, pubKey);

        addSubjectKID(certBuilder, pubKey);
        addAuthorityKID(certBuilder, caCert.getPublicKey());
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(3));
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(BASE_EKU));

        X509Certificate certificate = signCert(certBuilder, ppk);
        certificate.checkValidity(new Date());
        certificate.verify(caCert.getPublicKey());

        setPKCS9Info(certificate);

        return certificate;
    }

    public X509Certificate createClass1EndCert(X500Name sdn, PublicKey pubKey, KeyPair pKeyPair) throws Exception {

        PublicKey pPubKey = pKeyPair.getPublic();
        PrivateKey pPrivKey = pKeyPair.getPrivate();

        X500Name issuer = X500NameUtil.createClass1RootPrincipal();
        BigInteger sno = BigInteger.valueOf(System.currentTimeMillis());
        Date nb = new Date(System.currentTimeMillis() - HALF_DAY);
        Date na = new Date(nb.getTime() + FIVE_YEAR);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, sno, nb, na, sdn, pubKey);

        addSubjectKID(certBuilder, pubKey);
        addAuthorityKID(certBuilder, pPubKey);
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(BASE_EKU));
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(END_KEY_USAGE));

        X509Certificate certificate = signCert(certBuilder, pPrivKey);
        certificate.checkValidity(new Date());
        certificate.verify(pPubKey);

        setPKCS9Info(certificate);

        return certificate;
    }

    public X509Certificate createClass3EndCert(long sno, X500Name sdn, Map<String, String> exts, KeyPair keyPair,
                                               KeyPair pKeyPair) throws Exception {
        PublicKey pPubKey = pKeyPair.getPublic();
        PrivateKey pPrivKey = pKeyPair.getPrivate();

        X500Name idn = X500NameUtil.createClass3RootPrincipal();
        BigInteger _sno = BigInteger.valueOf(sno <= 0 ? System.currentTimeMillis() : sno);
        Date nb = new Date(System.currentTimeMillis() - HALF_DAY);
        Date na = new Date(nb.getTime() + FIVE_YEAR);
        PublicKey pubKey = keyPair.getPublic();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(idn, _sno, nb, na, sdn, pubKey);

        addSubjectKID(certBuilder, pubKey);
        addAuthorityKID(certBuilder, pPubKey);
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(MOST_EKU));
        certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(END_KEY_USAGE));
        if (exts != null) {
            Set<String> key = exts.keySet();
            for (Iterator<String> it = key.iterator(); it.hasNext();) {
                String oid = it.next();
                String value = exts.get(oid);
                if (!StringUtils.isBlank(value)) {
                    certBuilder.addExtension(new ASN1ObjectIdentifier(oid), false, new DEROctetString(value.getBytes()));
                }
            }
        }

        X509Certificate certificate = signCert(certBuilder, pPrivKey);
        certificate.checkValidity(new Date());
        certificate.verify(pPubKey);

        setPKCS9Info(certificate);

        return certificate;
    }

    public PKCS10CertificationRequest createCSR(X500Name x500Name, KeyPair keyPair) throws Exception {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(x500Name, publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA);
        ContentSigner signer = csBuilder.build(privateKey);
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        return csr;
    }

    public X509Certificate signCert(PKCS10CertificationRequest pkcs10CSR, X500Name issuer, KeyPair pKeyPair)
                                                                                                            throws Exception {
        SubjectPublicKeyInfo pkInfo = pkcs10CSR.getSubjectPublicKeyInfo();
        RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(pkInfo);
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
        KeyFactory kf = KeyFactory.getInstance(ALG_RSA);
        PublicKey publicKey = kf.generatePublic(rsaSpec);

        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(publicKey.getEncoded()));
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                                                                            issuer,
                                                                            BigInteger.valueOf(System.currentTimeMillis()),
                                                                            new Date(System.currentTimeMillis()
                                                                                     - MadDateConstant.ONE_DAY),
                                                                            new Date(System.currentTimeMillis()
                                                                                     + MadDateConstant.ONE_YEAR),
                                                                            pkcs10CSR.getSubject(), keyInfo);

        ContentSigner signer = new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(pKeyPair.getPrivate());
        X509Certificate signedCert = new JcaX509CertificateConverter().setProvider(JCE_PROVIDER).getCertificate(certBuilder.build(signer));
        signedCert.verify(pKeyPair.getPublic());

        return signedCert;
    }

    private static void setPKCS9Info(X509Certificate certificate) throws Exception {
        // X500Name subject = CertificateUtil.getSubject(certificate);
        // PKCS12BagAttributeCarrier attrCarrier = (PKCS12BagAttributeCarrier) certificate;
        // String friendlyName = CertificateUtil.getValue(subject.getRDNs(BCStyle.CN)[0]);
        // attrCarrier.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(friendlyName));
        // SubjectKeyIdentifier pubKeyId = new
        // JcaX509ExtensionUtils().createSubjectKeyIdentifier(certificate.getPublicKey());
        // attrCarrier.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, pubKeyId);
    }

    private static void addSubjectKID(X509v3CertificateBuilder certBuilder, PublicKey pubKey) throws Exception {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pubKey));
    }

    private static void addAuthorityKID(X509v3CertificateBuilder certBuilder, PublicKey pubKey) throws Exception {
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(pubKey));
    }

    private static void addCRLDistributionPoints(X509v3CertificateBuilder certBuilder) throws CertIOException {
        DistributionPoint[] distPoints = new DistributionPoint[1];
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, MAD_CRL_URL);
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointOne = new DistributionPointName(generalNames);
        distPoints[0] = new DistributionPoint(distPointOne, null, null);
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));
    }

    private static void addAuthorityInfoAccess(X509v3CertificateBuilder certBuilder) throws CertIOException {
        ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
        GeneralName crlName = new GeneralName(GeneralName.uniformResourceIdentifier,
                                              new DERIA5String(MadCertConstant.MAD_CA_URL));
        AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, crlName);
        GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier,
                                               new DERIA5String(MadCertConstant.MAD_OCSP_URL));
        AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, ocspName);
        aia_ASN.add(caIssuers);
        aia_ASN.add(ocsp);
        certBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));
    }

    private static X509Certificate signCert(X509v3CertificateBuilder certBuilder, PrivateKey pPrivKey) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(pPrivKey);
        return new JcaX509CertificateConverter().setProvider(JCE_PROVIDER).getCertificate(certBuilder.build(signer));
    }
}
