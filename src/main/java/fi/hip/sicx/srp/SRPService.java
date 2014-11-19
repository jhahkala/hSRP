package fi.hip.sicx.srp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.infinispan.Cache;
import org.infinispan.manager.DefaultCacheManager;

import com.caucho.hessian.server.HessianServlet;

public class SRPService extends HessianServlet implements SRPAPI {
    
    private static final long serialVersionUID = 2588238351912872652L;
    public static final String USERSLOGIN_CONFIG_FILE_OPT = "loginCacheConfigFile";
    private static Cache<String, User> _users = null;
    private static DefaultCacheManager _cacheManager = null;
    private static SecureRandom pseudoReandomGen = new SecureRandom();
    
    public SRPService(String configFile) throws IOException {

        File testFile = new File(configFile);
        if (!testFile.exists()) {
            throw new FileNotFoundException("Configuration file \"" + configFile + "\" not found.");
        }
        if (testFile.isDirectory()) {
            throw new FileNotFoundException("The file \"" + configFile + "\" given as a configuration file is a directory!");
        }

        Properties props = new Properties();
        props.load(new FileReader(configFile));
        String cacheConfig = props.getProperty(USERSLOGIN_CONFIG_FILE_OPT);

        testFile = new File(cacheConfig);
        if (!testFile.exists()) {
            throw new FileNotFoundException("Storage configuration file \"" + cacheConfig + "\" not found.");
        }
        if (testFile.isDirectory()) {
            throw new FileNotFoundException("The file \"" + cacheConfig + "\" given as a storage configuration file is a directory!");
        }
        if(_cacheManager == null){
            _cacheManager = new DefaultCacheManager(cacheConfig);
        }
        _users = _cacheManager.getCache("passwordsAndSessions");
//        System.out.println("users: " + _users);
//        System.out.println("props: " + props);
//        props.list(System.out);
    }

    public Cache<String, User> getSessionCache(){
        return _users;
    }

    public DefaultCacheManager getCacheManager(){
        return _cacheManager;
    }

    public void destroy(){
        System.out.println("!!!!!!!!!!!!!!!!!!!!!!! stopping **************************");
        _users.stop();
        _cacheManager.stop();
        _cacheManager = null;
    }


    public HostStartReply startHandshake(byte[] identity, BigInteger A) throws HandshakeException, CryptoException {
        Digest digest = new SHA512Digest();
        
        String name = new String(identity);
        User user = _users.get(name);
        // Check also the identity bytes to make sure the string conversion didn't cause clash
        if (!Arrays.equals(user.getIdentity(), identity)){
            throw new HandshakeException("Invalid name.");
        }

        SRP6Util.validatePublicValue(Params.N, A);
        
        BigInteger b = SRP6Util.generatePrivateValue(digest, Params.N, Params.g, pseudoReandomGen);
        BigInteger k = SRP6Util.calculateK(digest, Params.N, Params.g);
        BigInteger B = k.multiply(user.getVerifier()).mod(Params.N).add(Params.g.modPow(b, Params.N)).mod(Params.N);
        
        OpenHandshake handshake = new OpenHandshake(A, B, b);
        
        // get the user again to refresh it in case there are other logins happening.
        user = _users.get(name);
        user.addHandshake(handshake);
        _users.put(name, user);
        
        return new HostStartReply(user.getSalt(), B);
        
    }

    public byte[] finishHandShake(byte identity[], BigInteger A, byte M1[]) throws HandshakeException {
        Digest digest = new SHA512Digest();
        int padLength = (Params.N.bitLength() + 7) / 8;

        String name = new String(identity);
        User user = _users.get(name);
        
        // Check also the identity bytes to make sure the string conversion didn't cause clash
        if (user == null || !Arrays.equals(user.getIdentity(), identity)){
            throw new HandshakeException("Invalid name.");
        }

        OpenHandshake handshake = user.getHandshakes(A);
        
        if(handshake == null || !A.equals(handshake.getA())){
            throw new HandshakeException("No corresponding handshake found.");            
        }
        
        BigInteger u = SRP6Util.calculateU(digest, Params.N, A, handshake.getB());
        
        BigInteger S = calculateS(user.getVerifier(), A, handshake.getb(), u, Params.N);
       
        byte K[] = SRPUtil.hashBigInteger(S, padLength, digest);
        
        user.removeHandshake(A);
        Session testSession = new Session(K, S);
        user.addSession(testSession);
        
        _users.put(name, user);
//        System.out.println("handshakeaa Identity: " + new String(identity) + " session K: " + new String(K));
        return SRPUtil.calculateM2(A, M1, K, padLength, digest);
    }

    public void putVerifier(byte[] salt, byte[] identity, BigInteger v) {
        String name = new String(identity);
        User user = new User(name, identity, salt, v);
        // TODO: check that no user with that name or identity exists before
        _users.put(name, user);
        
    }
    
    public static BigInteger calculateS(BigInteger v, BigInteger A, BigInteger b, BigInteger u, BigInteger N){
        return v.modPow(u, N).multiply(A).mod(N).modPow(b, N);
    }



    public void logout(byte[] identity, byte[] K) {
        if (identity == null){
            throw new IllegalArgumentException("Cannot logout without giving an identity.");
        }
        if(K == null){
            throw new IllegalArgumentException("Cannot logout without giving a session.");
        }
        String name = new String(identity);
        User user = _users.get(new String(identity));
        if(user == null){
            // TODO: do fake stuff to make finding our if that user exists harder by timing analysis
            return;
        }
        int found = user.removeSession(K);
        if(found == 0){
            throw new IllegalArgumentException("Session not found");
        } else {
            _users.put(name, user);
        }
    }

    
}
