
package RSAKeysGenerator;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Generator {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

            while (true) {
                System.out.println("Nome do par de chaves (e.g.: server) ou 'exit' para sair");
                String nome = br.readLine();
                if( nome.equals("exit") ) break;

                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(1024);

                KeyPair pair = generator.generateKeyPair();

                ObjectOutputStream oosPubK = new ObjectOutputStream(new FileOutputStream(nome + "_pub.obj"));
                ObjectOutputStream oosPriK = new ObjectOutputStream(new FileOutputStream(nome + "_pri.obj"));

                oosPubK.writeObject(pair.getPublic());
                oosPriK.writeObject(pair.getPrivate());

                oosPriK.close();
                oosPubK.close();

                System.out.println("Done.");
            }
        } catch (IOException | NoSuchAlgorithmException ex) {
            Logger.getLogger(Generator.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
