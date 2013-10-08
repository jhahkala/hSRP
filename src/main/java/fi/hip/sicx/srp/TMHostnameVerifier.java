package fi.hip.sicx.srp;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import org.glite.security.util.HostNameChecker;

public class TMHostnameVerifier implements HostnameVerifier {

    @Override
    public boolean verify(String hostname, SSLSession session) {
        X509Certificate cert = null;
        try {
            cert = (X509Certificate) session.getPeerCertificates()[0];
        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
            return false;
        } 
        try {
            return HostNameChecker.checkHostName(hostname, cert);
        } catch (CertificateParsingException e) {
            e.printStackTrace();
            return false;
        }
    }

}
