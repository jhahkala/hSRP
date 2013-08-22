package fi.hip.sicx.srp;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoException;

/**
 * The API for doing the SRP-6a handshake.
 * http://srp.stanford.edu
 * 
 * @author hahkala
 *
 */
public interface SRPAPI {
    
    /**
     * Start the process by sending the identity and the A=g^a
     * 
     * @param identity the username, should be normalized according to SASLPrep (see: http://www.ietf.org/rfc/rfc4013.txt ).
     * @param A The client public value
     * @return the reply from the server, the salt and host public value B=kv+g^b
     * @throws HandshakeException 
     * @throws CryptoException 
     */
    public HostStartReply startHandshake(byte[] identity, BigInteger A) throws HandshakeException, CryptoException;
    
    /**
     * Finish the handshake by sending the proof that you know the session key, and receive the proof from the server.
     * @param M1 The proof H(H(N) xor H(g), H(I), s, A, B, K)
     * @return the proof from the server H(A, M, K)
     * @throws HandshakeException 
     */
    public byte[] finishHandShake(byte[] identity, BigInteger A, byte M1[]) throws HandshakeException;
    
    /**
     * Used to set the verifier, salt etc for the user.
     * 
     * @param salt
     * @param identity
     * @param x
     * @param v
     */
    public void putVerifier(byte salt[], byte identity[], BigInteger v);

}
