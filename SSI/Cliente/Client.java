package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static sun.security.pkcs11.wrapper.Functions.toHexString;

public class Client {

    // Acordo de Chaves Diffie-Hellman
    public static byte[] getSharedSecret(Socket soc) throws NoSuchAlgorithmException, InvalidParameterSpecException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhSkipParamSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("DH");
        keypairGen.initialize(dhSkipParamSpec);
        KeyPair keyPair = keypairGen.generateKeyPair();
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        byte[] publicKeyEnc = keyPair.getPublic().getEncoded();

        soc.getOutputStream().write(publicKeyEnc);

        byte[] publicServerKeyEnc = new byte[425];
        soc.getInputStream().read(publicServerKeyEnc);

        KeyFactory keyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicServerKeyEnc);
        PublicKey serverPubKey = keyFac.generatePublic(x509KeySpec);
        keyAgreement.doPhase(serverPubKey, true);

        byte[] sharedSecret = new byte[425];
        keyAgreement.generateSecret(sharedSecret, 0);

        return sharedSecret;
    }

    public static byte[][] derivateMasterKey(byte[] masterKey) throws NoSuchAlgorithmException {
        byte[][] res = new byte[2][];
        
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(masterKey);
        messageDigest.update("1".getBytes());
        res[0] = messageDigest.digest(); // k1
        messageDigest.reset();
        messageDigest.update(masterKey);
        messageDigest.update("2".getBytes());
        res[1] = messageDigest.digest(); // k2
        
        return res;
    }

    public static void main(String[] args) throws InvalidKeySpecException, IllegalStateException, ShortBufferException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        try {
            Socket soc = new Socket("localhost", Servidor.Server.PORT);

            byte[] masterKey = getSharedSecret(soc);
            byte[][] derivKeys = derivateMasterKey(masterKey);

            byte[] keyBytes = derivKeys[0]; // k1
            SecretKey key = new SecretKeySpec(keyBytes, 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

            byte[] iv = new byte[16];
            new Random().nextBytes(iv);
            soc.getOutputStream().write(iv); // Sends plain IV array

            // CTR - Counter Mode
            // NoPadding - Don't insert padding
            // Sends datagram immediately
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            CipherOutputStream cos = new CipherOutputStream(soc.getOutputStream(), cipher);

            while (soc.isConnected()) {
                int readed = br.read();
                cos.write(readed);
                cos.flush();
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | InvalidParameterSpecException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
