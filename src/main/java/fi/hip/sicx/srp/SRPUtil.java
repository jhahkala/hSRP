package fi.hip.sicx.srp;

import java.math.BigInteger;
import java.text.Normalizer;
import java.text.Normalizer.Form;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.BigIntegers;

public class SRPUtil {

    public static byte[] calculateM1(BigInteger N, BigInteger g, byte identity[], byte salt[], BigInteger A, BigInteger B, byte K[], int length, Digest digest){
        // get the necessary bytes first as we're using shared digest
        byte hashN[] = hashBigInteger(N, length, digest);
        byte hashg[] = hashBigInteger(g, length, digest);
        byte xorHashes[] = calculateXor(hashN, hashg);
        byte hashIdentity[] = hash(identity, digest);
        byte ABytes[] = getPadded(A, length);
        byte BBytes[] = getPadded(B, length);
        
        // hash all
        digest.update(xorHashes, 0, xorHashes.length);
        digest.update(hashIdentity, 0, hashIdentity.length);
        digest.update(salt, 0, salt.length);
        digest.update(ABytes, 0, ABytes.length);
        digest.update(BBytes, 0, BBytes.length);
        digest.update(K, 0, K.length);
        
        byte result[] = new byte[length];
        digest.doFinal(result, 0);
        return result;
        
    }

    public static byte[] calculateM2(BigInteger A, byte M1[], byte K[], int length, Digest digest){       
        
        byte ABytes[] = getPadded(A, length);
        
        digest.update(ABytes, 0, ABytes.length);
        digest.update(M1, 0, M1.length);
        digest.update(K, 0, K.length);
        
        byte result[] = new byte[length];
        digest.doFinal(result, 0);
    
        return result;
    }

    public static byte[] calculateXor(byte in1[], byte in2[]){
        if(in1.length != in2.length){
            throw new IllegalArgumentException("Can't xor different length arrays.");
        }
        byte result[] = new byte[in1.length];
        for(int i = 0; i < in1.length; i++){
            result[i] = (byte)(in1[i] ^ in2[i]);
        }
        
        return result;
    }

    public static byte[] getPadded(BigInteger n, int length)
    {
        byte[] bs = BigIntegers.asUnsignedByteArray(n);
        if (bs.length < length)
        {
            byte[] tmp = new byte[length];
            System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
            bs = tmp;
        }
        return bs;
    }

    public static byte[] hash(byte input[], Digest digest){
        digest.update(input, 0, input.length);
        int outSize = digest.getDigestSize();
        byte value[] = new byte[outSize];
        digest.doFinal(value, 0);
        return value;
    }

    public static byte[] hashBigInteger(BigInteger S, int length, Digest digest){
        byte SBits[] = getPadded(S, length);
        return hash(SBits, digest);        
    }
    
    public static byte[] stringBytes(String input){
        String normalized = Normalizer.normalize(input, Form.NFKC);
        return normalized.getBytes();
    }

}
