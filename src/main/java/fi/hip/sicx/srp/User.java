package fi.hip.sicx.srp;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;

public class User implements Serializable {

    private static final long serialVersionUID = -7589235896411209069L;
    private String m_name = null;
    private byte m_identity[] = null;
    private byte m_salt[] = null;
    private BigInteger m_v = null;
    private List<Session> m_sessions = null;
    private int m_failedLogins = 0;
    private HashMap<BigInteger, OpenHandshake> openLogins = new HashMap<BigInteger, OpenHandshake>();
    
    public User(String name, byte identity[], byte salt[], BigInteger verifier){
        m_name = name;
        m_identity = identity;
        m_salt = salt;
        m_v = verifier;
    }
    
    public String getName(){
        return m_name;
    }

    public byte[] getIdentity() {
        return m_identity;
    }    
    
    public byte[] getSalt() {
        return m_salt;
    }
    
    public BigInteger getVerifier(){
        return m_v;
    }
    
    public int getFailedLogins(){
        return m_failedLogins;
    }
    
    public int addFailedLogins(){
        return m_failedLogins++;
    }
    
    public List<Session> getSessions(){
        return m_sessions;
    }
    
    public void addSession(Session session){
        m_sessions.add(session);
    }
    
    public void addHandshake(OpenHandshake handshake){
        openLogins.put(handshake.getA(), handshake);
    }
    
    public OpenHandshake getHandshakes(BigInteger A){
        return openLogins.get(A);
    }
    
}
