package Cliente;

import Common.DiffieHellman;
import Common.Utils;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    private final static BigInteger n = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    private final static BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");

    ObjectOutputStream oos;
    ObjectInputStream ois;

    private final Cipher enc;
    private final Mac hmac;
    private final byte[] masterKey;
    private final PrivateKey clientPrivateKey;
    private final PublicKey serverPublicKey;

    public Client(String host, int port, String caFilePath, String privateKeyFile, String certPathServer) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, SignatureException, CertificateException {
        Socket soc = new Socket(host, port);
        oos = new ObjectOutputStream(soc.getOutputStream());
        ois = new ObjectInputStream(soc.getInputStream());

        File certPathFileServer = new File(certPathServer);
        FileInputStream fin1 = new FileInputStream(certPathFileServer);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin1);
        if (!Utils.validateCert(caFilePath, certPathServer)) {
            System.err.println("Certificados inválidos");
            System.exit(-1);
        }
        PublicKey publicKeyServer = certificate.getPublicKey();

        byte[] encodedKey = new byte[2048];
        FileInputStream fis = new FileInputStream(privateKeyFile);
        fis.read(encodedKey);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = (PrivateKey) keyFactory.generatePrivate(keySpec);
        this.clientPrivateKey = privKey;
        this.serverPublicKey = publicKeyServer;

        // Acordo de Chaves Diffie-Hellman
        DiffieHellman dh = new DiffieHellman(Client.n, Client.g);
        BigInteger Y = dh.getPublicParam();

        BigInteger X = (BigInteger) ois.readObject();
        oos.writeObject(Y);

        masterKey = dh.getAccordedSecretKey(X).toByteArray();
        byte[][] derivKeys = Utils.derivateMasterKey(masterKey);

        SecretKey key = new SecretKeySpec(derivKeys[0], 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

        byte[] byteIV = new byte[16];
        new Random().nextBytes(byteIV);
        oos.write(byteIV); // Sends plain IV array
        oos.flush();
        IvParameterSpec IVSpec = new IvParameterSpec(byteIV);

        // CTR - Counter Mode
        // NoPadding - Don't insert padding
        // Sends datagram immediately
        enc = Cipher.getInstance("AES/CTR/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, key, IVSpec);

        Cipher dec = Cipher.getInstance("AES/CTR/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, key, IVSpec);

        SealedObject signatureServer = (SealedObject) ois.readObject();
        byte[] tupleSigServer = (byte[]) signatureServer.getObject(dec);

        byte[] tupleSigClient = Utils.generateTupleSignature(Y, X, clientPrivateKey);
        SealedObject signatureClient = new SealedObject(tupleSigClient, enc);
        oos.writeObject(signatureClient);

        if (!Utils.verifyTupleSignature(X, Y, tupleSigServer, serverPublicKey)) {
            System.out.println("Man-In-The-Middle Detected");
            System.exit(-1);
        }

        SecretKey keyMAC = new SecretKeySpec(derivKeys[1], 0, 16, "HmacMD5");
        hmac = Mac.getInstance(keyMAC.getAlgorithm());
        hmac.init(keyMAC);
    }

    public void sendMessage(int msg) throws IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] buff = new byte[1];
        buff[0] = (byte) msg;

        byte[] cifra = enc.doFinal(buff);
        byte[] mac = hmac.doFinal(cifra); // computa o MAC

        oos.write(cifra);
        oos.write(mac);
        oos.flush();
    }

    public static void main(String[] args) throws CertificateException {
        try {
            Client c = new Client("localhost", 4567, "cacert.pem", "client_key.pk8", "server_cert.pem");
            System.out.println("Ligado ao Servidor com sucesso");

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            int readed;
            while ((readed = br.read()) != -1) {
                c.sendMessage(readed);
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | InvalidKeySpecException | SignatureException ex) {
            Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
