package fi.hip.sicx.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA512Digest;

public class SRPClient {
    
    private static SecureRandom pseudoReandomGen = new SecureRandom();
    
    
    public static BigInteger login(SRPAPI service, byte identity[], byte password[]) throws CryptoException{
        Digest digest = new SHA512Digest();
        
        // just to clarify the variables.
        BigInteger g = Params.g;
        BigInteger N = Params.N;
        
        int padLength = (N.bitLength() + 7) / 8;
        
        // Generate the public value A
        BigInteger a = SRP6Util.generatePrivateValue(digest, N, g, pseudoReandomGen);
        BigInteger A = g.modPow(a, N);
        
        HostStartReply reply = service.startHandshake(identity, A);
        
        byte salt[] = reply.getSalt();
        BigInteger B = SRP6Util.validatePublicValue(N, reply.getB());
        
        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        BigInteger x = SRP6Util.calculateX(digest, N, salt, identity, password);
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        
        BigInteger exp = u.multiply(x).add(a);
        BigInteger tmp = g.modPow(x, N).multiply(k).mod(N);
        BigInteger S = B.subtract(tmp).mod(N).modPow(exp, N);
        
        byte K[] = SRPUtil.hashBigInteger(S, padLength, digest);
        
        byte M1[] = SRPUtil.calculateM1(N, g, identity, salt, A, B, K, padLength, digest);
        
        byte M2[] = service.finishHandShake(M1);
        
        if(verifyM2(M2, A, M1, K, padLength, digest)){
            return S;
        } else {
            throw new CryptoException("Server sent a wrong reply, authentication failed! (Check that there is no compromise on server side)");
        }
        
    }
      
    public static boolean verifyM2(byte M2[], BigInteger A, byte M1[], byte K[], int length, Digest digest) {

        byte result[] = SRPUtil.calculateM2(A, M1, K, length, digest);
        
        if(result.length != M2.length){
            throw new IllegalArgumentException("Can't xor different length arrays.");
        }
        
        boolean validation = true;
        
        // go through all in every case to avoid timing differences.
        for(int i = 0; i < result.length; i++){
            if(result[i] != M2[i]){
                validation =  false;
            }
        }
        
        return validation;
    }
}
