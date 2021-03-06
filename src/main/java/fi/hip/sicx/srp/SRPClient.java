package fi.hip.sicx.srp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA512Digest;

public class SRPClient {
    
    private static SecureRandom pseudoReandomGen = new SecureRandom();
    
    public static void putVerifier(SRPAPI service, String name, String passwordString){
        BigInteger N = Params.N;
        BigInteger g = Params.g;

        Digest digest = new SHA512Digest();
        SecureRandom pseudoRandomGen = new SecureRandom();

        BigInteger random = SRP6Util.generatePrivateValue(digest, N, Params.g, pseudoRandomGen);

        int padLength = (N.bitLength() + 7) / 8;

        byte salt[] = SRPUtil.getPadded(random, padLength);
        byte identity[];
        byte password[];
        try {
            identity = SRPUtil.stringBytes(name);
            password = SRPUtil.stringBytes(passwordString);
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new IllegalArgumentException("username or password encoding failed.");
        }

        BigInteger x;
		try {
			x = SRPUtil.calculateXWithScrypt(N, salt, identity, password);
		} catch (IOException e) {
			e.printStackTrace();
			throw new RuntimeException("Internal error while calculating verifier: " + e.getLocalizedMessage());
		} catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new RuntimeException("Internal error while calculating verifier: " + e.getLocalizedMessage());
        }

        BigInteger verifier = g.modPow(x, N);

//        System.out.println("xxsalt: " + new String(salt) + " identity: " + new String(identity) + " verifier: " + verifier);

        service.putVerifier(salt, identity, verifier);

        
    }
    
    public static SessionKey login(SRPAPI service, String identity, String passwordString) throws CryptoException, HandshakeException{

        byte identityBytes[];
        byte passwordBytes[];
        try {
            identityBytes = SRPUtil.stringBytes(identity);
            passwordBytes = SRPUtil.stringBytes(passwordString);
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new HandshakeException("username or password encoding failed.");
        }

        return SRPClient.login(service, identityBytes, passwordBytes);
        
    }
    
    public static SessionKey login(SRPAPI service, byte identity[], byte password[]) throws CryptoException, HandshakeException{
        Digest digest = new SHA512Digest();
        
        // just to clarify the variables.
        BigInteger g = Params.g;
        BigInteger N = Params.N;
        
        int bytesLength = (N.bitLength() + 7) / 8;
        
        // Generate the public value A
        BigInteger a = SRP6Util.generatePrivateValue(digest, N, g, pseudoReandomGen);
        BigInteger A = g.modPow(a, N);
        
        HostStartReply reply = service.startHandshake(identity, A);
        
        byte salt[] = reply.getSalt();
       
        BigInteger B = SRP6Util.validatePublicValue(N, reply.getB());
        
        BigInteger u = SRP6Util.calculateU(digest, N, A, B);
        // check u
        BigInteger checku = u.mod(N);
        if(checku.equals(BigInteger.valueOf(0))){
            throw new HandshakeException("Invalid random scrambling value u. Probable attack.");
        }
        BigInteger x;
		try {
			x = SRPUtil.calculateXWithScrypt(N, salt, identity, password);
		} catch (IOException e) {
			e.printStackTrace();
			throw new HandshakeException("Internal error while calculating verifier:" + e.getLocalizedMessage());
		} catch (GeneralSecurityException e) {
            e.printStackTrace();
            throw new HandshakeException("Internal error while calculating verifier:" + e.getLocalizedMessage());
        }
        BigInteger k = SRP6Util.calculateK(digest, N, g);
        
        BigInteger exp = u.multiply(x).mod(N).add(a).mod(N);
        BigInteger tmp = g.modPow(x, N).multiply(k).mod(N);
        BigInteger S = B.subtract(tmp).mod(N).modPow(exp, N);
        
        byte K[] = SRPUtil.hashBigInteger(S, bytesLength, digest);
        
        byte M1[] = SRPUtil.calculateM1(N, g, identity, salt, A, B, K, bytesLength, digest);
        
        byte M2[] = service.finishHandShake(identity, A, M1);
        
        if(verifyM2(M2, A, M1, K, bytesLength, digest)){
            return new SessionKey(S,K);
        } else {
            throw new HandshakeException("Server xx sent a wrong reply, authentication failed! (Possible compromise on server side)");
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
