package Servidor;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HandleClient implements Runnable {
    private final CipherInputStream cis;
    private final int order;

    HandleClient(Socket soc, int order, Server server) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {        
        byte[] keyBytes = "0123456789ABCDEF".getBytes();
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        
        byte[] iv = new byte[16];
        soc.getInputStream().read(iv); // Receive plain IV array
        
        Cipher cipher = Cipher.getInstance("AES/CFB8/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        
        this.cis = new CipherInputStream(soc.getInputStream(), cipher);
        this.order = order;
    }

    @Override
    public void run() {
        try {
            int test;
            while ((test = cis.read()) != -1) {
                System.out.print((char) test);
            }

            System.out.println("=[" + this.order + "]=");
        } catch (IOException ex) {
            Logger.getLogger(HandleClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
