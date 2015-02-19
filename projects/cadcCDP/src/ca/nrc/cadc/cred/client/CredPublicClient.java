
package ca.nrc.cadc.cred.client;

import ca.nrc.cadc.cred.CertUtil;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.util.Base64;
import java.util.ArrayList;
import java.util.List;

public class CredPublicClient
{
    private static Logger LOGGER = Logger.getLogger(CredPublicClient.class);
    private URL baseServiceURL;

    // socket factory to use when connecting
    SSLSocketFactory sf;

    /**
     * Default, and only available constructor.
     * 
     * @param baseServiceURL
     *            The base service URL
     */
    public CredPublicClient(final URL baseServiceURL)
    {
        this.baseServiceURL = baseServiceURL;
    }

    public void delegate(X500Principal userDN, int days)
            throws MalformedURLException, IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            CertificateExpiredException, CertificateNotYetValidException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        final URL resourceURL = new URL(getBaseServiceURL()
                + resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("create step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("create step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_CREATED:
                String location = connection.getHeaderField("Location");
                X509Certificate cert = generateV3Certificate(
                        readCSR(getEncodedCSR(location, userDN)
                                .getBytes()), days * 24 * 60 * 60);
                X509Certificate[] chain = createProxyCertChain(cert);
                putSignedCert(location, chain, userDN);

                break;
            case HttpURLConnection.HTTP_OK:
                // break intentionally left out
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Creates the resource (private key, public key, CSR) for userDN.
     * Throws various exceptions when something goes wrong.
     * 
     * @param userDN
     * @return URL to the newly create resource
     * @throws IOException
     */
    public String createResoure(X500Principal userDN) throws IOException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        final URL resourceURL = new URL(getBaseServiceURL()
                + resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("create step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("create step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_CREATED:
                return connection.getHeaderField("Location");
            case HttpURLConnection.HTTP_OK:
                // break intentionally left out
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Delete the resource (private key, public key, CSR) for userDN.
     * Throws various exceptions when something goes wrong.
     * 
     * @param userDN
     * @throws IOException
     * @throws CertificateException
     */
    public void deleteResource(X500Principal userDN) throws IOException,
            CertificateException
    {
        String location = getLocation(userDN);
        final StringBuilder resourcePath = new StringBuilder(64);
        resourcePath.append(location);
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        final URL resourceURL = new URL(resourcePath.toString());

        LOGGER.debug("delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("DELETE");
        connection.setDoInput(true);
        connection.setDoOutput(false);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("delete step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("delete step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_NO_CONTENT:
                return;
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Accesses the Certificate Signing Request associated with a
     * user/location Base64 encoded
     * 
     * @param location
     *            URL of the resource that owns the CSR.
     * @return Base64 encoded CSR
     * @throws IOException
     * 
     */
    private String getEncodedCSR(String location, X500Principal userDN)
            throws IOException, InvalidKeyException,
            NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException,
            CertificateParsingException, CertificateExpiredException,
            CertificateNotYetValidException
    {
        final URL resourceURL = new URL(location + "/CSR");
        LOGGER.debug("get CSR step in delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get CSR step in delegate(), response code: "
                + responseCode);
        LOGGER.debug("get CSR step in delegate(), response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    byte[] csr = null;
                    InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    int bytesRead;
                    byte[] buffer = new byte[1024];
                    while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1)
                    {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                    csr = out.toByteArray();
                    in.close();
                    LOGGER.debug("Downloaded CSR of size: " + csr.length);
                    return new String(csr);

                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                return null;
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_FORBIDDEN:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Accesses the Certificate Signing Request associated with a user
     * 
     * @param userDN
     *            The DN of the user that owns the CSR.
     * @return CSR
     * @throws IOException
     * 
     */
    public String getEncodedCSR(X500Principal userDN) throws IOException,
            InvalidKeyException, CertificateEncodingException,
            CertificateParsingException, CertificateExpiredException,
            CertificateNotYetValidException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException
    {
        String location = getLocation(userDN);
        if (location == null)
        {
            throw new IllegalArgumentException(
                    "No certificate found for " + userDN);
        }
        return getEncodedCSR(location, userDN);
    }

    /**
     * Accesses the certificate associated with a user/location
     * 
     * @return X509Certificate from the CDP URL of the resource that owns
     *         the certificate
     * @throws IOException
     */
    public X509Certificate[] getCertificate(X500Principal userDN)
            throws IOException, InvalidKeyException,
            NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, CertificateEncodingException,
            CertificateParsingException, CertificateException
    {
        String location = getLocation(userDN);
        final URL resourceURL = new URL(location + "/certificate");
        LOGGER.debug("get certificate, URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get certificate, response code: " + responseCode);
        LOGGER.debug("get certificate, response message: "
                + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    int bytesRead;
                    byte[] buffer = new byte[1024];
                    while ((bytesRead = in.read(buffer, 0, buffer.length)) != -1)
                    {
                        out.write(buffer, 0, bytesRead);
                    }
                    out.flush();
                    byte[] certBuf = out.toByteArray();
                    in.close();

                    X509Certificate[] certs = SSLUtil
                            .readCertificateChain(SSLUtil
                                    .getCertificates(certBuf));
                    return certs;

                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                return null;
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Gets the URL corresponding to the resource in CDP
     * 
     * @return hash code used to access subject's resource in CDP
     * @throws IOException
     */
    public String getLocation(X500Principal userDN) throws IOException,
            CertificateException
    {
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(),
                    "UTF-8"));
        }

        final URL resourceURL = new URL(getBaseServiceURL()
                + resourcePath.toString());
        LOGGER.debug("get hash, URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.connect();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER.debug("get hash, response code: " + responseCode);
        LOGGER.debug("get hash, response message: " + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                try
                {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(connection
                                    .getInputStream()));
                    String hash = reader.readLine();
                    if (reader.readLine() != null)
                    {
                        throw new CertificateException(
                                "Only one hash expected");
                    }
                    return baseServiceURL + "/" + hash;
                }
                catch (UnsupportedEncodingException e)
                {
                    throw new RuntimeException(
                            "UTF-8 encoding not supported");
                }
            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * Puts a signed certificate associated with a user/location.
     * 
     * @param cert Signed certificate to put.
     * @throws IOException
     * @throws CertificateException
     */
    public void putSignedCert(X509Certificate cert) throws IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateException
    {
        X500Principal delegatedUser = cert.getSubjectX500Principal();
        String location = getLocation(delegatedUser);
        putSignedCert(location, new X509Certificate[] { cert }, delegatedUser);
    }
    
    // append certficate chain with the specified cert to make a valid proxy cert
    private X509Certificate[] createProxyCertChain(X509Certificate cert)
    {
        AccessControlContext ac = AccessController.getContext();
        Subject subject = Subject.getSubject(ac);
        if (subject != null)
        {
            Set<X509CertificateChain> cc = subject.getPublicCredentials(X509CertificateChain.class);
            if (cc.size() > 0)
            {
               X509CertificateChain xcc = cc.iterator().next();
               X509Certificate[] chain = xcc.getChain();
               X509Certificate[] ret = new X509Certificate[chain.length + 1];
               ret[0] = cert;
               for (int i=0; i<chain.length; i++)
               {
                   ret[i+1] = chain[i];
               }
               return ret;
            }
        }
        throw new IllegalStateException("current Subject does not contain a certficate chain");
        
    }

    /**
     * Puts a signed certificate associated with a user/location
     * 
     * @param location
     *            URL of the resource that owns the certificate
     * @param cert
     *            Signed certificate to put.
     * @throws IOException
     */
    private void putSignedCert(String location, X509Certificate[] certs,
            X500Principal userDN) 
            throws IOException,
            InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException
    {
        LOGGER.debug("putSignedCert: " + userDN + " chain length: " + certs.length);
        
        final StringBuilder resourcePath = new StringBuilder(64);
        // user does not have the group created. Through a POST.
        // the server generates one and returns it to the user
        resourcePath.append(location);
        resourcePath.append("/certificate");
        if (userDN != null)
        {
            resourcePath.append("?DN=");
            resourcePath.append(URLEncoder.encode(userDN.getName(), "UTF-8"));
        }

        final URL resourceURL = new URL(resourcePath.toString());
        LOGGER.debug("put certificate step in delegate(), URL=" + resourceURL);
        HttpURLConnection connection = openConnection(resourceURL);
        connection.setRequestMethod("PUT");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);

        OutputStream os = connection.getOutputStream();
        PEMWriter writer = new PEMWriter(new OutputStreamWriter(os));
        for (X509Certificate c : certs)
        {
            writer.writeObject(c);
        }

        writer.flush();
        writer.close();

        String responseMessage = connection.getResponseMessage();
        int responseCode = connection.getResponseCode();
        LOGGER
                .debug("put certificate step in delegate(), response code: "
                        + responseCode);
        LOGGER
                .debug("put certificate step in delegate(), response message: "
                        + responseMessage);

        switch (responseCode)
        {
            case HttpURLConnection.HTTP_OK:
                LOGGER.debug("Certificate uploaded");
                break;

            case HttpURLConnection.HTTP_CONFLICT:
                // break intentionally left out
            case HttpURLConnection.HTTP_NOT_FOUND:
                // parent node not found
                // break intentionally left out
            case HttpURLConnection.HTTP_BAD_REQUEST:
                // duplicate group
                throw new IllegalArgumentException(responseMessage);
            case HttpURLConnection.HTTP_UNAUTHORIZED:
                throw new AccessControlException(responseMessage);
            default:
                throw new RuntimeException("Unexpected failure mode: "
                        + responseMessage + "(" + responseCode + ")");
        }

    }

    /**
     * 
     * @return the base service URL
     */
    public URL getBaseServiceURL()
    {
        return baseServiceURL;
    }

    /**
     * Open a HttpsURLConnection with a SocketFactory created based on
     * user credentials.
     * 
     * @param url
     * @return UTLConnection returns an open https connection to URL
     * @throws IOException
     */
    protected HttpsURLConnection openConnection(final URL url)
            throws IOException
    {
        if (!url.getProtocol().equals("https"))
        {
            throw new IllegalArgumentException("Wrong protocol: "
                    + url.getProtocol() + ". GMS works on https only");
        }
        if (sf == null)
        {
            // lazy initialization of socket factory
            AccessControlContext ac = AccessController.getContext();
            Subject subject = Subject.getSubject(ac);
            sf = SSLUtil.getSocketFactory(subject);
        }
        HttpsURLConnection con = (HttpsURLConnection) url
                .openConnection();
        if (sf != null)
            con.setSSLSocketFactory(sf);
        return con;
    }

    public X509Certificate generateV3Certificate(
            PKCS10CertificationRequest csr, int lifetime)
            throws InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException,
            CertificateEncodingException, CertificateParsingException,
            CertificateExpiredException, CertificateNotYetValidException
    {

        AccessControlContext ac = AccessController.getContext();
        Subject subject = Subject.getSubject(ac);
        X509CertificateChain chain = null;
        if (subject != null)
        {
            Set<X509CertificateChain> certs = subject
                    .getPublicCredentials(X509CertificateChain.class);
            if (certs.size() > 0)
                chain = certs.iterator().next();
        }
        if (chain == null)
        {
            throw new AccessControlException("Subject not authorized");
        }

        return CertUtil.generateCertificate(csr, lifetime, chain);
    }

    /**
     * Parses a byte array and constructs the corresponding
     * PKCS10CertificationRequest
     * 
     * @param code
     *            bytes containing the CSR
     * @return PKCS10CertificationRequest
     * @throws IOException
     */
    public static PKCS10CertificationRequest readCSR(byte[] code)
            throws IOException
    {
        byte[] crt = getCSR(code);
        return new PKCS10CertificationRequest(crt);
    }

    static byte[] getCSR(byte[] certBuf) throws IOException
    {
        BufferedReader rdr = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(certBuf)));
        String line = rdr.readLine();
        StringBuffer base64 = new StringBuffer();
        while (line != null)
        {
            if (line.startsWith("-----BEGIN CERTIFICATE REQUEST-"))
            {
                LOGGER.debug(line);
                line = rdr.readLine();
                while (line != null
                        && !line
                                .startsWith("-----END CERTIFICATE REQUEST-"))
                {
                    LOGGER.debug(line + " (" + line.length() + ")");
                    base64.append(line.trim());
                    line = rdr.readLine();
                }
                LOGGER.debug(line);
                line = null; // break from outer loop
            }
            else
                line = rdr.readLine();
        }
        rdr.close();
        String encoded = base64.toString();
        LOGGER.debug("CERTIFICATE REQUEST: " + encoded);
        // now: base64 -> byte[]
        byte[] ret = Base64.decode(encoded);
        LOGGER.debug("RSA private key: " + ret.length + " bytes");

        return ret;
    }
}
