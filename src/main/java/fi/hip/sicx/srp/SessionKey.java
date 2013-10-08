package fi.hip.sicx.srp;

import java.math.BigInteger;

public class SessionKey {
    private BigInteger _S = null;
    private byte _K[] = null;
    
    public SessionKey(BigInteger S, byte K[]){
        _S = S;
        _K = K;
    }
    
    public BigInteger getS(){
        return _S;
    }
    
    public byte[] getK(){
        return _K;
    }

}
