package Cliente;

import Common.DiffieHellman;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private final static BigInteger n = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    private final static BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    
    private final InputStream is;
    private final OutputStream os;
    private final Cipher cipher;
    private final Mac hmac;
    
    private final byte[] masterKey;

    public Client(String host, int port) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Socket soc = new Socket(host, port);
        is = soc.getInputStream();
        os = soc.getOutputStream();
        
        masterKey = getSharedSecret();

        byte[][] derivKeys = derivateMasterKey(masterKey);

        byte[] keyBytes = derivKeys[0]; // k1
        SecretKey key = new SecretKeySpec(keyBytes, 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        os.write(iv); // Sends plain IV array

        // CTR - Counter Mode
        // NoPadding - Don't insert padding
        // Sends datagram immediately
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        SecretKey keyMAC = new SecretKeySpec(derivKeys[1], 0, 16, "HmacMD5");
        hmac = Mac.getInstance(keyMAC.getAlgorithm());
        hmac.init(keyMAC);
    }

    // Acordo de Chaves Diffie-Hellman
    public byte[] getSharedSecret() throws IOException {
        DiffieHellman dh = new DiffieHellman(Client.n, Client.g);
        BigInteger publicKey = dh.getPublicKey();

        byte[] publicKeyServerBytes = new byte[128];
        is.read(publicKeyServerBytes);
        os.write(publicKey.toByteArray());
        BigInteger publicServerKey = new BigInteger(publicKeyServerBytes);

        return dh.getPrivateKey(publicServerKey).toByteArray();
    }

    public byte[][] derivateMasterKey(byte[] masterKey) throws NoSuchAlgorithmException {
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

    public void sendMessage(int msg) throws IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] buff = new byte[1];
        buff[0] = (byte) msg;

        byte[] cifra = cipher.doFinal(buff);
        byte[] mac = hmac.doFinal(cifra); // computa o MAC

        os.write(cifra);
        os.write(mac);
        os.flush();
    }

    public static void main(String[] args) {
        try {
            Client c = new Client("localhost", 4567);
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            int readed;
            while ((readed = br.read()) != -1) {
                c.sendMessage(readed);
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
