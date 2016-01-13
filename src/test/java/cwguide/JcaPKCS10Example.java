package cwguide;

import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.ALG_SIG_SHA256_RSA;
import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.JCE_PROVIDER;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.madding.shared.encrypt.ProviderUtil;

/**
 * A simple example showing generation and verification of a PKCS#10 request.
 */
public class JcaPKCS10Example
{
    public static void main(String[] args)
            throws Exception
    {
        ProviderUtil.addBCProvider();

        String sigName = ALG_SIG_SHA256_RSA;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", JCE_PROVIDER);

        kpg.initialize(1024);

        KeyPair kp = kpg.genKeyPair();

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);

        x500NameBld.addRDN(BCStyle.C, "AU");
        x500NameBld.addRDN(BCStyle.ST, "Victoria");
        x500NameBld.addRDN(BCStyle.L, "Melbourne");
        x500NameBld.addRDN(BCStyle.O, "The Legion of the Bouncy Castle");

        X500Name subject = x500NameBld.build();

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());

        ExtensionsGenerator extGen = new ExtensionsGenerator();

        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "feedback-crypto@bouncycastle.org")));

        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());

        PKCS10CertificationRequest req1 = requestBuilder.build(new JcaContentSignerBuilder(sigName).setProvider(JCE_PROVIDER).build(kp.getPrivate()));

        if (req1.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(JCE_PROVIDER).build(kp.getPublic())))
        {
            System.out.println(sigName + ": PKCS#10 request verified.");
        }
        else
        {
            System.out.println(sigName + ": Failed verify check.");
        }
    }
}
