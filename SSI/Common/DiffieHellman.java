/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package Common;

import java.math.BigInteger;
import java.util.Random;

/**
 *
 * @author Paulo
 */
public class DiffieHellman {
    private final BigInteger n;
    private final BigInteger  g;
    
    private final BigInteger random;
    private final BigInteger publicKey;
    
    
    public DiffieHellman(BigInteger n, BigInteger  g) {
        this.n = n;
        this.g = g;
        
        this.random = new BigInteger(1024, new Random());
        this.publicKey = g.modPow(this.random, n);
    }
    
    public BigInteger getPublicKey() {
        return this.publicKey;
    }
    
    public BigInteger getPrivateKey(BigInteger external) {
        return external.modPow(random, n);
    }
}
