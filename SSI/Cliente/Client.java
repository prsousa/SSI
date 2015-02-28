package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    public static void main(String[] args) {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        try {
            Socket soc = new Socket("localhost", Servidor.Server.PORT);

            byte[] keyBytes = "0123456789ABCDEF".getBytes();
            SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, "RC4");
            
            // With RC4 the datagram is sent immediately without buffering to compleat a block
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            CipherOutputStream cos = new CipherOutputStream(soc.getOutputStream(), cipher);

            while (soc.isConnected()) {
                int readed = br.read();
                cos.write(readed);
                cos.flush();
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
