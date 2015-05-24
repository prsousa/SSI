
package Common;

import java.math.BigInteger;
import java.util.Random;

public class DiffieHellman {
    private final BigInteger n;
    private final BigInteger  g;
    
    private final BigInteger random;
    private final BigInteger publicParam;
    
    
    public DiffieHellman(BigInteger n, BigInteger  g) {
        this.n = n;
        this.g = g;
        
        this.random = new BigInteger(1024, new Random());
        this.publicParam = g.modPow(this.random, n);
    }
    
    public BigInteger getPublicParam() {
        return this.publicParam;
    }
    
    
    public BigInteger getAccordedSecretKey(BigInteger external) {
        return external.modPow(random, n);
    }
}
