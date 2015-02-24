package Servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;

public class Server {

    public static int PORT = 4567;
    private final AtomicInteger order;

    public Server() {
        this.order = new AtomicInteger();
    }

    public static void main(String[] args) {
        Server server = new Server();
        try {
            ServerSocket sc = new ServerSocket(PORT);

            while (true) {
                Socket s = sc.accept();
                HandleClient client = new HandleClient(s, server.order.incrementAndGet(), server);
                new Thread(client).start();
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
