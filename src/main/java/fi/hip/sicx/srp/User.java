package fi.hip.sicx.srp;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;


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
        if(m_sessions == null){
            m_sessions = new LinkedList<Session>();
        }
        m_sessions.add(session);
    }
    
    public int removeSession(byte[] K){
        int found = 0;
        if(K == null){
            throw new IllegalArgumentException("No session ID given, can't remove a session without ID.");
        }
        for(Session session: m_sessions){
            if(Arrays.equals(K, session._sessionId)){
                m_sessions.remove(session);
                found++;
                // intentionally continue to search for more occucences of the same session.
            }
        }
        return found;
    }
    
    public Session findSession(byte K[]){
        if(K == null){
            throw new IllegalArgumentException("No session ID given, can't find a session.");
        }
        for(Session session: m_sessions){
//            System.out.println("Checking:");
//            System.out.println("1: " + new String(Hex.encode(K)) + " len: " + K.length);
//            System.out.println("2: " + new String(Hex.encode(session._sessionId)) + " len: " + session._sessionId.length);
            
            if(Arrays.equals(K, session._sessionId)){
//                System.out.println("match");
                return session;
            }else{
//                System.out.println("no match");
            }
        }
        return null;
    }
    
    public void addHandshake(OpenHandshake handshake){
        openLogins.put(handshake.getA(), handshake);
    }
    
    public void removeHandshake(BigInteger A){
        openLogins.remove(A);
    }
    
    public OpenHandshake getHandshakes(BigInteger A){
        return openLogins.get(A);
    }
    
}
