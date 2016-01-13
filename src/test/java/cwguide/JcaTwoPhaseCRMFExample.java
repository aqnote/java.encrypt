package cwguide;

import static com.madding.shared.encrypt.cert.bc.constant.MadBCConstant.JCE_PROVIDER;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;

import com.madding.shared.encrypt.ProviderUtil;

/**
 * Basic example of CRMF which tells a CA to send the certificate back encrypted.
 */
public class JcaTwoPhaseCRMFExample
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
                    .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build().getEncoded());

        // check that proof-of-possession is present.
        if (certReqMsg.hasProofOfPossession())
        {
            System.out.println("Proof-of-Possession found");
        }
        else
        {
            System.out.println("No proof-of-possession found");
        }
    }
}
