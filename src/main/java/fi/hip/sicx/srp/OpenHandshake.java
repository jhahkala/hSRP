package fi.hip.sicx.srp;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Date;

public class OpenHandshake  implements Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = -8010581197492942099L;
    private BigInteger m_A;
    private BigInteger m_B;
    private BigInteger m_b;
    private Date m_started;

    public OpenHandshake(BigInteger A, BigInteger B, BigInteger b) {
        m_started = new Date();
        m_A = A;
        m_B = B;
        m_b = b;
        
    }
    
    public BigInteger getA(){
        return m_A;
    }
    
    public BigInteger getB(){
        return m_B;
    }
    
    public BigInteger getb(){
        return m_b;
    }

    public Date getStarted(){
        return m_started;
    }

}
