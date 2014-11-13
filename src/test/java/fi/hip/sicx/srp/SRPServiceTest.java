package fi.hip.sicx.srp;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import fi.hip.sicx.srp.hessian.HessianSRPProxyFactory;


public class SRPServiceTest {

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
            String url = "https://localhost:40669/MetaService";
            HessianSRPProxyFactory factory = HessianSRPProxyFactory.getFactory(TRUSTED_CLIENT_CONFIG_FILE);
            SRPAPI service = (SRPAPI) factory.create(SRPAPI.class, url);
            
            String name = "UserNamexxx";
            String passwordString = "PassWordaaa";
            SRPClient.putVerifier(service, name, passwordString);
            
            byte identity[] = SRPUtil.stringBytes(name);
            byte password[] = SRPUtil.stringBytes(passwordString);

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
