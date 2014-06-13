package fi.hip.sicx.srp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.junit.Test;

public class SRPAPITest {
    private static SecureRandom pseudoRandomGen = new SecureRandom();

    @Test
    public void testSRP() throws CryptoException, HandshakeException, IOException, GeneralSecurityException{
        SRPService service = new SRPService("src/test/srp-purge.conf");
        
        BigInteger N = Params.N;
        BigInteger g = Params.g;

        String name = "UserNamexxx";
        String passwordString = "PassWordaaa";
        
        Digest digest = new SHA512Digest();
        
        BigInteger random = SRP6Util.generatePrivateValue(digest, N, Params.g, pseudoRandomGen);
        
        int padLength = (N.bitLength() + 7) / 8;
        
        
        byte salt[] = SRPUtil.getPadded(random, padLength);
        byte identity[] = SRPUtil.stringBytes(name);
        byte password[] = SRPUtil.stringBytes(passwordString);
        
        BigInteger x = SRPUtil.calculateXWithScrypt(N, salt, identity, password);
        
        BigInteger verifier = g.modPow(x, N);
        
        System.out.println("salt: " + salt+ " identity: " +identity+ " verifier: "+ verifier);
        
        service.putVerifier(salt, identity, verifier);

        SessionKey session = SRPClient.login(service, identity, password);
        
        System.out.println("K: " + new String(session.getK()) + " S: " + session.getS());
    }
    
    /**
     * @param args
     */
    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
