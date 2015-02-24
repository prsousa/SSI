package RC4;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RC4 {

    public static String help() {
        StringBuilder sb = new StringBuilder();
        sb.append("Usage:\n");
        sb.append("\t prog -genkey <keyfile>\n");
        sb.append("\t prog -enc <keyfile> <infile> <outfile>\n");
        sb.append("\t prog -dec <keyfile> <infile> <outfile>\n");
        return sb.toString();
    }

    private static byte[] generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("RC4");
        return keyGen.generateKey().getEncoded();
    }

    private static byte[] encrypt(SecretKey key, byte[] plain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plain);
    }
    
    private static byte[] decrypt(SecretKey key, byte[] crypto) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RC4");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(crypto);
    }

    public static void main(String args[]) {
        try {
            if (args.length < 1) {
                System.err.println(help());
                return;
            }

            switch (args[0].toLowerCase()) {
                case "-genkey": {
                    if (args.length < 2) {
                        System.err.println(help());
                        return;
                    }

                    byte[] secretKey = generateKey();
                    FileOutputStream output = new FileOutputStream(new File(args[1]));
                    output.write(secretKey);
                    break;
                }
                case "-enc": {
                    if (args.length < 4) {
                        System.err.println(help());
                        return;
                    }

                    File keyFile = new File(args[1]);
                    FileInputStream keyFileStream = new FileInputStream(keyFile);
                    byte[] key = new byte[(int) keyFile.length()];
                    keyFileStream.read(key, 0, key.length);
                    SecretKey originalKey = new SecretKeySpec(key, 0, key.length, "RC4");

                    File plainFile = new File(args[2]);
                    FileInputStream plainFileStream = new FileInputStream(plainFile);
                    byte[] plain = new byte[(int) plainFile.length()];
                    plainFileStream.read(plain, 0, plain.length);
                    
                    byte[] crypted = encrypt(originalKey, plain);
                    
                    FileOutputStream outputCrypted = new FileOutputStream(new File(args[3]));
                    outputCrypted.write(crypted);

                    break;
                }
                case "-dec": {
                    if (args.length < 4) {
                        System.err.println(help());
                        return;
                    }

                    File keyFile = new File(args[1]);
                    FileInputStream keyFileStream = new FileInputStream(keyFile);
                    byte[] key = new byte[(int) keyFile.length()];
                    keyFileStream.read(key, 0, key.length);
                    SecretKey originalKey = new SecretKeySpec(key, 0, key.length, "RC4");

                    File cryptedFile = new File(args[2]);
                    FileInputStream cryptFileStream = new FileInputStream(cryptedFile);
                    byte[] crypto = new byte[(int) cryptedFile.length()];
                    cryptFileStream.read(crypto, 0, crypto.length);
                    
                    byte[] plain = encrypt(originalKey, crypto);
                    
                    FileOutputStream outputPlain = new FileOutputStream(new File(args[3]));
                    outputPlain.write(plain);
                    
                    break;
                }
                default:
                    help();
                    return;
            }
        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(RC4.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
