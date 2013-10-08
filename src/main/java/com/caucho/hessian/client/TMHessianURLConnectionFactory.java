package com.caucho.hessian.client;


import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;

import org.glite.security.trustmanager.ContextWrapper;

import com.caucho.hessian.client.HessianConnection;
import com.caucho.hessian.client.HessianConnectionFactory;
import com.caucho.hessian.client.HessianProxyFactory;
import com.caucho.hessian.client.HessianURLConnection;

/**
 * Class to set up the ssl connection for the hessian communication on the client side.
 * 
 * It's not necessary to maintain a copy of the class HessianURLConnection when
 * the TMHessianURLConnectionFactory is in the com.caucho.hessian.client package
 * as it can then use the protected methods in the hessianURLConnection.
 * 
 * @author hahkala
 * 
 */
public class TMHessianURLConnectionFactory implements HessianConnectionFactory {

    private HessianProxyFactory _proxyFactory = null;
    private ContextWrapper _wrapper = null;
    private HostnameVerifier _verifier = null;

    @Override
    public HessianConnection open(URL url) throws IOException {

        URLConnection conn = url.openConnection();

        if (url.toString().trim().startsWith("https:")) {
            if (conn instanceof HttpsURLConnection) {
                HttpsURLConnection sslConnection = (HttpsURLConnection) conn;
                if (_wrapper != null && _verifier != null) {
                    sslConnection.setSSLSocketFactory(_wrapper.getSocketFactory());
                    sslConnection.setHostnameVerifier(_verifier);
                }
            }
        }

        // HttpURLConnection httpConn = (HttpURLConnection) conn;
        // httpConn.setRequestMethod("POST");
        // conn.setDoInput(true);

        long connectTimeout = _proxyFactory.getConnectTimeout();

        if (connectTimeout >= 0)
            conn.setConnectTimeout((int) connectTimeout);

        conn.setDoOutput(true);

        long readTimeout = _proxyFactory.getReadTimeout();

        if (readTimeout > 0) {
            try {
                conn.setReadTimeout((int) readTimeout);
            } catch (Throwable e) {
                // ignore failure
            }
        }

        /*
         * // Used chunked mode when available, i.e. JDK 1.5. if
         * (_proxyFactory.isChunkedPost() && conn instanceof HttpURLConnection)
         * { try { HttpURLConnection httpConn = (HttpURLConnection) conn;
         * 
         * httpConn.setChunkedStreamingMode(8 * 1024); } catch (Throwable e) { }
         * }
         */

        return new HessianURLConnection(url, conn);
    }

    /**
     * @return the _wrapper
     */
    public ContextWrapper getWrapper() {
        return _wrapper;
    }

    /**
     * @param _wrapper
     *            the _wrapper to set
     */
    public void setWrapper(ContextWrapper wrapper) {
        _wrapper = wrapper;
    }

    /**
     * @return the _verifier
     */
    public HostnameVerifier getVerifier() {
        return _verifier;
    }

    /**
     * @param _verifier
     *            the _verifier to set
     */
    public void setVerifier(HostnameVerifier verifier) {
        _verifier = verifier;
    }

    @Override
    public void setHessianProxyFactory(HessianProxyFactory factory) {
        _proxyFactory = factory;

    }

}
