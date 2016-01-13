package cwguide;

import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.ALG_SIG_SHA256_RSA;
import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.JCE_PROVIDER;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.madding.shared.encrypt.ProviderUtil;

/**
 * Basic example of CRMF using a signature for proof-of-possession
 */
public class JcaBasicCRMFExample
{
    public static void main(String[] args)
        throws Exception
    {
        ProviderUtil.addBCProvider();

        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", JCE_PROVIDER);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setSubject(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder(ALG_SIG_SHA256_RSA).setProvider(JCE_PROVIDER).build(kp.getPrivate()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        // check that internal check on popo signing is working okay

        if (certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(JCE_PROVIDER).build(kp.getPublic())))
        {
            System.out.println("CRMF message verified");
        }
        else
        {
            System.out.println("CRMF verification failed");
        }
    }
}
