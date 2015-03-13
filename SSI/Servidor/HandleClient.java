package Servidor;

import Common.DiffieHellman;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HandleClient implements Runnable {

    private final int order;
    private final Mac hmac;
    private final InputStream is;
    private final Cipher cipher;
    
    private final static BigInteger n = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    private final static BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    
    // Acordo de Chaves Diffie-Hellman
    static byte[] getSharedSecret(Socket soc) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, ShortBufferException {
        DiffieHellman dh = new DiffieHellman(HandleClient.n, HandleClient.g);
        BigInteger publicKey = dh.getPublicKey();
        
        soc.getOutputStream().write(publicKey.toByteArray());
        byte[] publicKeyServerBytes = new byte[128];
        soc.getInputStream().read(publicKeyServerBytes);
                
        BigInteger publicClientKey = new BigInteger(publicKeyServerBytes);
        
        return dh.getPrivateKey(publicClientKey).toByteArray();
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
        is = soc.getInputStream();
        
        byte[] masterKey = getSharedSecret(soc);
        byte[][] derivKeys = derivateMasterKey(masterKey);

        byte[] keyBytes = derivKeys[0];
        SecretKey key = new SecretKeySpec(keyBytes, 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

        byte[] iv = new byte[16];
        is.read(iv); // Receive plain IV array
        
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        
        SecretKey keyMAC = new SecretKeySpec(derivKeys[1], 0, 16, "HmacMD5");
        hmac = Mac.getInstance(keyMAC.getAlgorithm());
        hmac.init(keyMAC);

        this.order = order;
    }

    @Override
    public void run() {
        try {
            byte[] buff = new byte[1];
            
            int cifra;
            byte[] macReceived = new byte[16];
            while ((cifra = is.read()) != -1) {

                is.read(macReceived); // recebe o MAC da mensagem
                
                hmac.update((byte) cifra);
                byte[] macComputed = hmac.doFinal(); // computa o MAC da cifra recebida
                
                if( validateMacs(macComputed, macReceived) ) {
                    buff[0] = (byte) cifra;
                    byte[] msg = cipher.doFinal( buff );
                    
                    System.out.print((char) msg[0]);
                    
                } else {
                    System.err.println("Mensagem Corrompida"); // se os MACs não coincidirem houve quebra da integridade
                }
            }
            
            System.out.println("=[" + this.order + "]=");
        } catch (IOException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(HandleClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
