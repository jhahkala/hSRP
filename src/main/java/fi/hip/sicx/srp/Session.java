package fi.hip.sicx.srp;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.util.Arrays;

public class Session implements Serializable{
    private static final long serialVersionUID = 5543860796792300230L;
    public Date _created = new Date();
    public Date _expires = null;
    public BigInteger _secret = null;
    public byte _sessionId[] = null;
    public Date _lastUsed = new Date();
    
    /**
     * Creates new Session with given sessionId, that will expire in one day.
     * 
     * @param sessionId
     */
    public Session(byte sessionId[], BigInteger secret){
        _sessionId = sessionId;
        _secret = secret;
        Calendar test = new GregorianCalendar();
        test.add(Calendar.DATE, 1);
        _expires = test.getTime();
    }
    
    /**
     * Creates new Session with given sessionId, that will expire at the given time.
     * 
     * @param sessionId The session id for this session.
     * @param expires the time when the session will expire.
     */
    public Session(byte sessionId[], BigInteger secret, Date expires){
        _sessionId = sessionId;
        _secret = secret;
        _expires = expires;
    }
    
    
    /**
     * Checks that the session id matches this session and that the session hasn't expired.
     * Also updates the last used time.
     * 
     * @param sessionId The session id to check.
     * @return true in case the session is valid.
     */
    public boolean isValid(byte sessionId[]){
        if(checkValid(sessionId)){
            _lastUsed = new Date();
            return true;
        }
        return false;
    }
    
    /**
     * Checks that the session id matches this session and the session hasn't expired.
     * 
     * @param sessionId the session id to check.
     * @return true in case the session is valid.
     */
    private boolean checkValid(byte sessionId[]){
        if(sessionId == null){
            return false;
        }

        // sanity check
        if(Arrays.areEqual(sessionId, Params.zeroBytes)){
            return false;
        }
        
        if(!Arrays.areEqual(sessionId, _sessionId)){
            return false;
        }
        
        Date currentDate = new Date();
        
        if(!currentDate.before(_expires)){
            return false;
        }
        
        // sanity check
        if(!currentDate.after(_created)){
            return false;
        }
        
        return true;
    }

}
