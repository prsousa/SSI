
package Common;

import java.io.File;
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
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
    
    public static X509Certificate getCertFromFile(String certFilePath)
            throws Exception {
        X509Certificate cert = null;
        File certFile = new File(certFilePath);
        FileInputStream certFileInputStream = new FileInputStream(certFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(certFileInputStream);
        return cert;
    }

    public static PKIXParameters createParams(String anchorFile) throws Exception {
        TrustAnchor anchor = new TrustAnchor(getCertFromFile(anchorFile), null);
        Set anchors = Collections.singleton(anchor);
        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(false);
        return params;
    }

    public static CertPath createPath(String[] certs) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List list = new ArrayList();
        for (int i = 1; i < certs.length; i++) {
            list.add(getCertFromFile(certs[i]));
        }

        return cf.generateCertPath(list);
    }

    public static boolean validateCert(String caCertFilePath, String certFilePath) {
        CertPathValidatorResult cpvr = null;

        try {
            PKIXParameters params = createParams(caCertFilePath);
            String[] files = new String[2];
            files[0] = caCertFilePath;
            files[1] = certFilePath;

            CertPath cp = createPath(files);
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            cpvr = cpv.validate(cp, params);
        } catch (Exception e) {
            System.out.println(e.getMessage());

        }

        return cpvr != null;
    }
}
