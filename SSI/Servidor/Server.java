package Servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class Server {
    private final AtomicInteger order;

    public Server() {
        this.order = new AtomicInteger();
    }

    public static void main(String[] args) throws CertificateException {
        Server server = new Server();
        try {
            ServerSocket sc = new ServerSocket(4567);

            while (true) {
                Socket s = sc.accept();
                HandleClient client = new HandleClient(s, server.order.incrementAndGet(), server, "cacert.pem", "server_key.pk8", "client_cert.pem");
                new Thread(client).start();
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | InvalidKeySpecException | IllegalStateException | ShortBufferException | NoSuchProviderException | SignatureException | IllegalBlockSizeException | ClassNotFoundException | BadPaddingException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
