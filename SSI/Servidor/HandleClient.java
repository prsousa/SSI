package Servidor;

import Common.DiffieHellman;
import Common.Utils;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class HandleClient implements Runnable {

    private final int order;
    private final Mac hmac;
    private final ObjectInputStream ois;
    private final ObjectOutputStream oos;
    private final Cipher dec;

    private final PrivateKey serverPrivateKey;
    private final PublicKey clientPublicKey;

    private final static BigInteger n = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    private final static BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");

    HandleClient(Socket soc, int order, Server server, String caFilePath, String pk8, String certPathClient) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalStateException, ShortBufferException, NoSuchProviderException, SignatureException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, CertificateException {
        ois = new ObjectInputStream(soc.getInputStream());
        oos = new ObjectOutputStream(soc.getOutputStream());

        File certPathFileClient = new File(certPathClient);
        FileInputStream fin1 = new FileInputStream(certPathFileClient);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) f.generateCertificate(fin1);
        if (!Utils.validateCert(caFilePath, certPathClient)) {
            System.err.println("Certificados inválidos");
            System.exit(-1);
        }
        PublicKey publicKeyClient = certificate.getPublicKey();

        byte[] encodedKey = new byte[2048]; // read from file
        FileInputStream fis = new FileInputStream(pk8);
        fis.read(encodedKey);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privKey = (PrivateKey) keyFactory.generatePrivate(keySpec);

        this.serverPrivateKey = privKey;
        this.clientPublicKey = publicKeyClient;

        // Acordo de Chaves Diffie-Hellman
        DiffieHellman dh = new DiffieHellman(HandleClient.n, HandleClient.g);
        BigInteger X = dh.getPublicParam(); // X

        oos.writeObject(X);
        BigInteger Y = (BigInteger) ois.readObject(); // Y

        byte[] masterKey = dh.getAccordedSecretKey(Y).toByteArray();
        byte[][] derivKeys = Utils.derivateMasterKey(masterKey);

        SecretKey key = new SecretKeySpec(derivKeys[0], 0, 16, "AES"); // apenas utiliza os primeiros 16 bytes da chave

        byte[] byteIV = new byte[16];
        ois.read(byteIV); // Receive plain IV array
        IvParameterSpec IVSpec = new IvParameterSpec(byteIV);

        dec = Cipher.getInstance("AES/CTR/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, key, IVSpec);

        Cipher enc = Cipher.getInstance("AES/CTR/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, key, IVSpec);

        byte[] tupleSigServer = Utils.generateTupleSignature(X, Y, serverPrivateKey);
        SealedObject signatureServer = new SealedObject(tupleSigServer, enc);
        oos.writeObject(signatureServer);

        SealedObject signatureClient = (SealedObject) ois.readObject();
        byte[] tupleSigClient = (byte[]) signatureClient.getObject(dec);

        if (!Utils.verifyTupleSignature(Y, X, tupleSigClient, clientPublicKey)) {
            System.out.println("Man-In-The-Middle Detected");
            System.exit(-1);
        }

        SecretKey keyMAC = new SecretKeySpec(derivKeys[1], 0, 16, "HmacMD5");
        hmac = Mac.getInstance(keyMAC.getAlgorithm());
        hmac.init(keyMAC);

        this.order = order;
    }

    @Override
    public void run() {
        System.out.println("Cliente ligado com sucesso");
        try {
            byte[] buff = new byte[1];

            int cifra;
            byte[] macReceived = new byte[16];
            while ((cifra = ois.read()) != -1) {

                ois.read(macReceived); // recebe o MAC da mensagem

                hmac.update((byte) cifra);
                byte[] macComputed = hmac.doFinal(); // computa o MAC da cifra recebida

                if (Utils.validateMacs(macComputed, macReceived)) {
                    buff[0] = (byte) cifra;
                    byte[] msg = dec.doFinal(buff);

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
