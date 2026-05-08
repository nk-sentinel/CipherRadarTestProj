package benchmark;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class JcaTlsTests {

    // EXPECTED: TLS | 1.3 | - | info | quantum-safe
    public SSLContext tlsv13() throws Exception {
        return SSLContext.getInstance("TLSv1.3"); // GOOD
    }

    // EXPECTED: TLS | 1.2 | - | info | quantum-safe
    public SSLContext tlsv12() throws Exception {
        return SSLContext.getInstance("TLSv1.2"); // OK
    }

    // EXPECTED: TLS | 1.1 | - | high | quantum-vulnerable
    public SSLContext tlsv11() throws Exception {
        return SSLContext.getInstance("TLSv1.1"); // DEPRECATED
    }

    // EXPECTED: TLS | 1.0 | - | critical | quantum-vulnerable
    public SSLContext tlsv10() throws Exception {
        return SSLContext.getInstance("TLSv1"); // BAD
    }

    // EXPECTED: SSL | 3.0 | - | critical | broken
    public SSLContext sslv3() throws Exception {
        return SSLContext.getInstance("SSL"); // BAD: SSLv3
    }

    // EXPECTED: X509TrustManager | - | - | critical | quantum-vulnerable
    // Trust-all TrustManager — accepts any certificate
    public TrustManager[] trustAll() {
        return new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {} // BAD
                public void checkServerTrusted(X509Certificate[] certs, String authType) {} // BAD
            }
        };
    }

    // EXPECTED: HostnameVerifier | - | - | critical | quantum-vulnerable
    // Hostname verifier bypass
    public HostnameVerifier bypassHostname() {
        return (hostname, session) -> true; // BAD: always returns true
    }

    // EXPECTED: TLS | 1.0,1.1 | - | high | quantum-vulnerable
    // Mixed protocol versions
    public void mixedProtocols(SSLServerSocket socket) {
        socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2"}); // BAD: includes deprecated
    }

    // EXPECTED: TLS | - | - | high | quantum-vulnerable
    // Weak cipher suites
    public void weakCipherSuites(SSLServerSocket socket) {
        socket.setEnabledCipherSuites(new String[]{
            "TLS_RSA_WITH_RC4_128_SHA",       // BAD: RC4
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",  // BAD: 3DES
            "TLS_RSA_WITH_AES_256_GCM_SHA384" // OK
        });
    }

    // EXPECTED: TLS | 1.2,1.3 | - | info | quantum-safe
    // Good TLS config via SSLParameters
    public void goodSSLParams(SSLServerSocket socket) {
        SSLParameters params = new SSLParameters();
        params.setProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        socket.setSSLParameters(params);
    }
}
