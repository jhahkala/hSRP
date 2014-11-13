package fi.hip.sicx.srp.hessian;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.glite.security.trustmanager.ContextWrapper;

import com.caucho.hessian.client.HessianProxyFactory;
import com.caucho.hessian.client.TMHessianURLConnectionFactory;
import com.caucho.hessian.io.HessianRemoteObject;

public class HessianSRPProxyFactory extends HessianProxyFactory {
    
    public static HessianSRPProxyFactory getFactory(String configFileName) throws FileNotFoundException, IOException, GeneralSecurityException{
        File configFile = new File(configFileName);
        Properties props = new Properties();
        props.load(new FileReader(configFile));
        ContextWrapper wrapper = new ContextWrapper(props, false);

        TMHostnameVerifier hostVerifier = new TMHostnameVerifier();
        HessianSRPProxyFactory factory = new HessianSRPProxyFactory();
        TMHessianURLConnectionFactory connectionFactory = new TMHessianURLConnectionFactory();
        connectionFactory.setWrapper(wrapper);
        connectionFactory.setVerifier(hostVerifier);
        connectionFactory.setHessianProxyFactory(factory);
        factory.setConnectionFactory(connectionFactory);

        return factory;
        
    }
    
    /**
     * Creates a new proxy with the specified URL. The returned object is a proxy with the interface specified by api.
     * 
     * <pre>
     * String url = "http://localhost:8080/ejb/hello");
     * HelloHome hello = (HelloHome) factory.create(HelloHome.class, url);
     * </pre>
     * 
     * @param api the interface the proxy class needs to implement
     * @param url the URL where the client object is located.
     * 
     * @return a proxy to the object with the specified interface.
     */
    public Object create(Class<?> api, URL url, ClassLoader loader) {
        if (api == null)
            throw new NullPointerException("api must not be null for HessianSRPProxyFactory.create()");
        InvocationHandler handler = null;

        handler = new HessianSRPProxy(url, this, api);

        return Proxy.newProxyInstance(loader, new Class[] { api, HessianRemoteObject.class }, handler);
    }

}
