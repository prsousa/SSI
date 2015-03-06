package DiffieHellman;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.DHParameterSpec;

public class DiffieHellman {
    private final BigInteger n;
    private final BigInteger  g;
    
    private final BigInteger random;
    private final BigInteger param;
    
    
    public DiffieHellman(BigInteger n, BigInteger  g) {
        this.n = n;
        this.g = g;
        
        this.random = new BigInteger(1024, new Random());
        this.param = g.modPow(this.random, n);
    }
    
    public BigInteger getParam() {
        return this.param;
    }
    
    public BigInteger computeKey(BigInteger external) {
        return external.modPow(random, n);
    }
    
    
    public static void main(String[] args) {
        try {
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            paramGen.init(1024);
            
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
            
            BigInteger n = dhSpec.getP();
            BigInteger g = dhSpec.getG();
            
            DiffieHellman Alice = new DiffieHellman(n, g);
            DiffieHellman Bob = new DiffieHellman(n, g);
            
            BigInteger publicAliceParam = Alice.getParam();
            BigInteger publicBobParam = Bob.getParam();
            
            BigInteger aliceKey = Alice.computeKey(publicBobParam);
            BigInteger bobKey = Bob.computeKey(publicAliceParam);
            
            System.out.println(aliceKey);
            System.out.println(bobKey);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
