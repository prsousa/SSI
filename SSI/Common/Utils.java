/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Common;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author Paulo
 */
public class Utils {

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
        if (a.length != b.length) {
            return false;
        }

        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    public static Key loadKeyFile(String src) {
        Key res = null;
        try {

            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(src));
            res = (Key) ois.readObject();
            ois.close();

        } catch (IOException | ClassNotFoundException ex) {
            System.err.println(ex.getMessage());
            //Logger.getLogger(HandleClient.class.getName()).log(Level.SEVERE, null, ex);
        }

        return res;
    }

    public static byte[] generateTupleSignature(BigInteger X, BigInteger Y, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(X.toByteArray());
        sig.update(Y.toByteArray());

        return sig.sign();
    }

    public static boolean verifyTupleSignature(BigInteger X, BigInteger Y, byte[] externalSignature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(X.toByteArray());
        sig.update(Y.toByteArray());

        return sig.verify(externalSignature);
    }
}
