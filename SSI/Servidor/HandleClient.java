package Servidor;

import static Cliente.Client.derivateMasterKey;
import static Cliente.Client.getSharedSecret;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HandleClient implements Runnable {

    private final CipherInputStream cis;
    private final int order;
    private final Mac mac;

    // Acordo de Chaves Diffie-Hellman
    static byte[] getSharedSecret(Socket soc) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, ShortBufferException {
        byte[] clientPubKeyEnc = new byte[426];
        soc.getInputStream().read(clientPubKeyEnc);

        KeyFactory keyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
        PublicKey clientPubKey = keyFac.generatePublic(x509KeySpec);

        DHParameterSpec dhParamSpec = ((DHPublicKey) clientPubKey).getParams();

        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("DH");
        keypairGen.initialize(dhParamSpec);
        KeyPair keyPair = keypairGen.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        byte[] publicKeyEnc = keyPair.getPublic().getEncoded();
        soc.getOutputStream().write(publicKeyEnc);

        keyAgreement.doPhase(clientPubKey, true);

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
    
    public static boolean validateMacs(byte[] a, byte[] b) {
        if(a.length != b.length) {
            return false;
        }
        
        for(int i = 0; i < a.length; i++) {
            if(a[i] != b[i]) {
                return false;
            }
        }
        
        return true;
    }
    
    HandleClient(Socket soc, int order, Server server) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
        byte[] masterKey = getSharedSecret(soc);
        byte[][] derivKeys = derivateMasterKey(masterKey);

        byte[] keyBytes = derivKeys[0];
        SecretKey key = new SecretKeySpec(keyBytes, 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

        byte[] iv = new byte[16];
        soc.getInputStream().read(iv); // Receive plain IV array

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        this.cis = new CipherInputStream(soc.getInputStream(), cipher);

        SecretKey keyMAC = new SecretKeySpec(derivKeys[1], 0, 16, "HmacMD5");
        mac = Mac.getInstance(keyMAC.getAlgorithm());
        mac.init(keyMAC);

        this.order = order;
    }

    @Override
    public void run() {
        try {
            int msg;
            byte[] macReceived = new byte[16];
            while ((msg = cis.read()) != -1) {
                System.out.print((char) msg);
                
                cis.read(macReceived); // recebe o MAC da mensagem
                
                mac.update((byte) msg);
                byte[] macComputed = mac.doFinal(); // computa o MAC da mensagem recebida
                if( !validateMacs(macComputed, macReceived) ) {
                    System.err.println("Mensagem Corrompida"); // se os MACs não coincidirem houve quebra da integridade
                }
            }

            System.out.println("=[" + this.order + "]=");
        } catch (IOException ex) {
            Logger.getLogger(HandleClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
