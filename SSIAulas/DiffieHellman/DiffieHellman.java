package DiffieHellman;

import java.math.BigInteger;
import java.util.Random;

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
        BigInteger n = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
        BigInteger g = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
        
        DiffieHellman Alice = new DiffieHellman(n, g);
        DiffieHellman Bob = new DiffieHellman(n, g);
        
        BigInteger publicAliceParam = Alice.getParam();
        BigInteger publicBobParam = Bob.getParam();
        
        BigInteger aliceKey = Alice.computeKey(publicBobParam);
        BigInteger bobKey = Bob.computeKey(publicAliceParam);
        
        System.out.println(aliceKey);
        System.out.println(bobKey);
    }
}
