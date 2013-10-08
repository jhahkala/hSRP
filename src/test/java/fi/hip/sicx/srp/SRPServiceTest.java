package fi.hip.sicx.srp;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.glite.security.trustmanager.ContextWrapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.caucho.hessian.client.HessianProxyFactory;
import com.caucho.hessian.client.TMHessianURLConnectionFactory;


public class SRPServiceTest {

    private static SecureRandom pseudoRandomGen = new SecureRandom();

    public static final String TEST_USER = "CN=trusted client,OU=Relaxation,O=Utopia,L=Tropic,C=UG";
    public static final String TEST_USER2 = "CN=trusted clientserver,OU=Relaxation,O=Utopia,L=Tropic,C=UG";
    public static final String TRUSTED_CLIENT_CONFIG_FILE = "src/test/srp-client.conf";
    public static final String SERVER_PURGE_CONFIG_FILE = "src/test/srp-purge.conf";

    SRPServer server;

    @Before
    public void setarrserver() {
        System.out.println("****Start");
        // server = new MetaServer();
        // try {
        // server.run(40666, false);
        // } catch (Exception e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
    }

    @After
    public void endserver() {
        System.out.println("****Stop");
        // try {
        // server.stop();
        // } catch (Exception e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
    }
    
    public void setup() throws Exception {
        server = new SRPServer();
        server.configure(SERVER_PURGE_CONFIG_FILE);
        server.start();
        File configFile = new File(TRUSTED_CLIENT_CONFIG_FILE);
        Properties props = new Properties();
        props.load(new FileReader(configFile));
        ContextWrapper wrapper = new ContextWrapper(props, false);
        HttpsURLConnection.setDefaultSSLSocketFactory(wrapper.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(new TMHostnameVerifier());         
        
    }

    /**
     * @param args
     * @throws Exception
     */
    @Test
    public void testHandshake() throws Exception {
        try {
            server = new SRPServer();
            server.configure(SERVER_PURGE_CONFIG_FILE);
            server.start();
            
            // client
            File configFile = new File(TRUSTED_CLIENT_CONFIG_FILE);
            Properties props = new Properties();
            props.load(new FileReader(configFile));
            ContextWrapper wrapper = new ContextWrapper(props, false);
            
            TMHostnameVerifier hostVerifier = new TMHostnameVerifier();         
            
            String url = "https://localhost:40669/MetaService";
            HessianProxyFactory factory = new HessianProxyFactory();
            TMHessianURLConnectionFactory connectionFactory = new TMHessianURLConnectionFactory();
            connectionFactory.setWrapper(wrapper);
            connectionFactory.setVerifier(hostVerifier);
            connectionFactory.setHessianProxyFactory(factory);
            factory.setConnectionFactory(connectionFactory);
            SRPAPI service = (SRPAPI) factory.create(SRPAPI.class, url);
            
            BigInteger N = Params.N;
            BigInteger g = Params.g;

            String name = "UserNamexxx";
            String passwordString = "PassWordaaa";
            
            Digest digest = new SHA512Digest();
            
            BigInteger random = SRP6Util.generatePrivateValue(digest, N, Params.g, pseudoRandomGen);
            
            int padLength = (N.bitLength() + 7) / 8;
            
            
            byte salt[] = SRPUtil.getPadded(random, padLength);
            byte identity[] = SRPUtil.stringBytes(name);
            byte password[] = SRPUtil.stringBytes(passwordString);
            
            BigInteger x = SRP6Util.calculateX(digest, N, salt, identity, password);
            
            BigInteger verifier = g.modPow(x, N);
            
            System.out.println("salt: " + salt+ " identity: " +identity+ " verifier: "+ verifier);
            
            service.putVerifier(salt, identity, verifier);

            SRPClient.login(service, identity, password);
             
        } finally {
            if (server != null) {
                server.stop();
            }
        }

    }
    /**
     * @param args
     */
    public static void main(String[] args) {
        // TODO Auto-generated method stub

    }

}
