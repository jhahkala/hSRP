package fi.hip.sicx.srp;

import org.bouncycastle.util.encoders.Hex;

/**
 * Class for representing and handling a session token.
 * 
 * @author hahkala
 *
 */
public class SessionToken {

    private byte _K[] = null;
    private byte _identity[] = null;

    public SessionToken(byte identity[], byte K[]){
        if(K == null){
            throw new IllegalArgumentException("Null is not allowed for K.");
        }
        if(identity == null){
            throw new IllegalArgumentException("Null is not allowed for identity.");
        }
        _K = K;
        _identity = identity;
    }
    
    public SessionToken(String token){
        if(token == null){
            throw new IllegalArgumentException("Null is not allowed for token.");
        }
        String parts[] = token.split("#");
        if(parts.length != 2){
            throw new IllegalArgumentException("Token has wrong number of '#' chars. (" + parts.length + ") when there should be 1.");
        }
        // force at least 2 byte identity, and limit to 256 as a sanity check
        int len = parts[0].length();
        if (len < 2 || len > 256){
            throw new IllegalArgumentException("Identity string lenght is wrong (" + len + ") when it should be between 2 and 256.");
        }
        _identity = SRPUtil.stringBytes(parts[0]);
        len = parts[1].length();
        if (len < 8 || len > 1024){
            throw new IllegalArgumentException("Hash string lenght is wrong (" + len + ") when it should be between 8 and 256.");
        }
        _K = Hex.decode(parts[1]);
        
    }
    
    public byte[] getHash(){
        return _K;
    }
    
    public byte[] getIdentity(){
        return _identity;
    }
    
    public String toString(){
        return new String(_identity) + "#" + new String(Hex.encode(_K));
    }
    
}
