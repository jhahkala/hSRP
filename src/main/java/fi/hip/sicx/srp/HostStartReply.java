package fi.hip.sicx.srp;

import java.math.BigInteger;

public class HostStartReply {
    
    private byte m_salt[] = null;
    private BigInteger m_B = null;
    
    public HostStartReply(byte salt[], BigInteger B){
        m_salt = salt;
        m_B = B;
    }
    
    public byte[] getSalt(){
        return m_salt;
    }
    
    public BigInteger getB(){
        return m_B;
    }

}
