package fi.hip.sicx.srp;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glite.security.trustmanager.ContextWrapper;

public class SRPServer {

    private Server _server = null;
    public static final String PORT_OPT = "port";
    public static final String HOST_OPT = "host";
    
    public SRPServer(){
    }
    
    public void join() throws InterruptedException{
        _server.join();
    }
    
    public void stop() throws Exception{
        if(_server != null){
            _server.stop();
        }
    }
    
    public void start() throws Exception{
        _server.start();
    }
    
    public void configure(String filename) throws IOException, GeneralSecurityException{
        if(filename == null){
            throw new NullPointerException("Configuration file can't be null.");
        }
        File configFile = new File(filename);
        if(!configFile.exists() || configFile.isDirectory()){
            throw new IOException("Configuration file \"" + configFile + "\" does not exist or is a directory.");
        }
        Properties props = new Properties();
        props.load(new FileReader(configFile));
        
        SslContextFactory factory = new SslContextFactory();
        factory.setSslContext((new ContextWrapper(props, false)).getContext());
        factory.setWantClientAuth(false);
        factory.setNeedClientAuth(false);
        SslSelectChannelConnector connector = new SslSelectChannelConnector(factory);
        
        int port = Integer.parseInt(props.getProperty(PORT_OPT));
        String host = props.getProperty(HOST_OPT);
        
        connector.setPort(port);
        connector.setHost(host);

        _server = new Server(port);
        _server.setSendServerVersion(false);
        _server.setSendDateHeader(false);
        _server.setConnectors(new Connector[] { connector });
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        _server.setHandler(context);

        context.addServlet(new ServletHolder(new SRPService(filename)), "/*");
        System.out.println("Server configured: " + _server);

    }

    /**
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        if(args.length < 1){
            System.out.println("SRPServer needs the configuration file as an argument!");
            System.exit(2);
        }
       
        if(args[0] == null){
            System.out.println("SRPServer needs the configuration file as an argument!");
            System.exit(2);                        
        }
        
        SRPServer server = new SRPServer();
        server.configure(args[0]);
        server.start();
        server.join();
        
        
    }

}
