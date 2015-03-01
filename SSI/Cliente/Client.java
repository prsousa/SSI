package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    public static void main(String[] args) {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        try {
            Socket soc = new Socket("localhost", Servidor.Server.PORT);

            byte[] keyBytes = "0123456789ABCDEF".getBytes();
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
            
            byte[] iv = new byte[16];
            new Random().nextBytes(iv);
            soc.getOutputStream().write(iv); // Sends plain IV array
            
            // CBC - Cipher Block Chaining
            // Blocks until buffer is complete
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            
            CipherOutputStream cos = new CipherOutputStream(soc.getOutputStream(), cipher);
            
            while (soc.isConnected()) {
                int readed = br.read();
                cos.write(readed);
                cos.flush();
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
