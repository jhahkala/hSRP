package fi.hip.sicx.srp;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class Session {
    public Date created = new Date();
    public Date expires = null;
    public BigInteger _sessionId = null;
    public Date lastUsed = new Date();
    
    public Session(BigInteger sessionId){
        _sessionId = sessionId;
        Calendar test = new GregorianCalendar();
        test.add(Calendar.DATE, 1);
        expires = test.getTime();
    }
    
    public boolean isValid(BigInteger sessionId){
        if(checkValid(sessionId)){
            lastUsed = new Date();
            return true;
        }
        return false;
    }
    
    private boolean checkValid(BigInteger sessionId){
        if(sessionId == null){
            return false;
        }

        // sanity check
        if(sessionId.equals(new BigInteger("0"))){
            return false;
        }
        
        if(!sessionId.equals(_sessionId)){
            return false;
        }
        
        Date currentDate = new Date();
        
        if(!currentDate.before(expires)){
            return false;
        }
        
        // sanity check
        if(!currentDate.after(created)){
            return false;
        }
        
        return true;
    }

}
