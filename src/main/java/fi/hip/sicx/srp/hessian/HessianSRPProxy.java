package fi.hip.sicx.srp.hessian;


import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

import com.caucho.hessian.client.HessianConnection;
import com.caucho.hessian.client.HessianProxy;
import com.caucho.hessian.client.HessianProxyFactory;

public class HessianSRPProxy extends HessianProxy {

    /** */
    private static final long serialVersionUID = 3744566286788170542L;
    private String m_SRPSession;

    protected HessianSRPProxy(URL url, HessianProxyFactory factory, Class<?> type) {
        super(url, factory, type);
    }

    protected HessianSRPProxy(URL url, HessianProxyFactory factory) {
        super(url, factory);
    }

    /**
     * Method that allows subclasses to add request headers such as cookies.
     * Default implementation is empty.
     */
    @Override
    protected void addRequestHeaders(HessianConnection conn) {
        conn.addHeader("Content-Type", "x-application/hessian");
        if (m_SRPSession != null) {
            try {
                conn.addHeader("SRPSession", URLEncoder.encode(m_SRPSession, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        String basicAuth = _factory.getBasicAuth();

        if (basicAuth != null)
            conn.addHeader("Authorization", basicAuth);
    }

    /**
     * Sets the cookie that will be set for all connections with this proxy.
     * 
     * @param session The cookie to use, set to null to remove previously set cookie.
     */
    public void setSession(String session) {
        m_SRPSession = session;
    }

}
