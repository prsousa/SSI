package DiffieHellman;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import static sun.security.pkcs11.wrapper.Functions.toHexString;

public class DiffieHellman {

    public static void main(String[] args) {
        try {
            DHParameterSpec dhSkipParamSpec;
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
            aliceKpairGen.initialize(dhSkipParamSpec);
            KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
            aliceKeyAgree.init(aliceKpair.getPrivate());

            byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

            // Bob
            KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
            PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

            DHParameterSpec dhParamSpec = ((DHPublicKey) alicePubKey).getParams();

            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamSpec);
            KeyPair bobKpair = bobKpairGen.generateKeyPair();

            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKpair.getPrivate());

            byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

            KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
            x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
            PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
            aliceKeyAgree.doPhase(bobPubKey, true);

            bobKeyAgree.doPhase(alicePubKey, true);

            byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
            int aliceLen = aliceSharedSecret.length;

            byte[] bobSharedSecret = new byte[aliceLen];
            
            
            bobKeyAgree.generateSecret(bobSharedSecret, 0);

            System.out.println( toHexString(aliceSharedSecret) );
            System.out.println( toHexString(bobSharedSecret) );
            
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidAlgorithmParameterException | InvalidKeyException | InvalidKeySpecException | IllegalStateException | ShortBufferException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
