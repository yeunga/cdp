/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2010.                            (c) 2010.
 * National Research Council            Conseil national de recherches
 * Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 * All rights reserved                  Tous droits reserves
 *
 * NRC disclaims any warranties         Le CNRC denie toute garantie
 * expressed, implied, or statu-        enoncee, implicite ou legale,
 * tory, of any kind with respect       de quelque nature que se soit,
 * to the software, including           concernant le logiciel, y com-
 * without limitation any war-          pris sans restriction toute
 * ranty of merchantability or          garantie de valeur marchande
 * fitness for a particular pur-        ou de pertinence pour un usage
 * pose.  NRC shall not be liable       particulier.  Le CNRC ne
 * in any event for any damages,        pourra en aucun cas etre tenu
 * whether direct or indirect,          responsable de tout dommage,
 * special or general, consequen-       direct ou indirect, particul-
 * tial or incidental, arising          ier ou general, accessoire ou
 * from the use of the software.        fortuit, resultant de l'utili-
 *                                      sation du logiciel.
 *
 *
 * @author adriand
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.cred.server;

import ca.nrc.cadc.auth.AuthMethod;
import java.io.BufferedWriter;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMWriter;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.server.actions.DelegationAction;
import ca.nrc.cadc.cred.server.actions.DelegationActionFactory;
import ca.nrc.cadc.io.ByteCountWriter;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.log.WebServiceLogInfo;
import ca.nrc.cadc.net.ResourceNotFoundException;
import java.io.PrintWriter;

/**
 * Servlet used to download a proxy certificate (PEM file) for the caller or an 
 * optionally specified identity.
 * 
 */
public class ProxyServlet extends HttpServlet
{
    public static final String TRUSTED_PRINCIPALS_PARAM = "trustedPrincipals";
    public static final String DSNAME = "datasource";
    public static final String CATALOG = "catalog";
    public static final String SCHEMA = "schema";
    
    private static final long serialVersionUID = 2740612605831266225L;
    private static Logger LOGGER = Logger.getLogger(ProxyServlet.class);

    // The set of trusted principals allowed to call this service
    private Map<X500Principal, Float> trustedPrincipals = new HashMap<X500Principal, Float>();
    private String dataSourceName;
    private String database;
    private String schema;

    /**
     * Read the configuration.
     * @param config
     * @throws javax.servlet.ServletException
     */
    @Override
    public void init(final ServletConfig config) 
        throws ServletException
    {
        super.init(config);
        // get the trusted principals from config
        String trustedPrincipalsValue = config.getInitParameter(TRUSTED_PRINCIPALS_PARAM);
        if (trustedPrincipalsValue != null)
        {
            StringTokenizer st = new StringTokenizer(trustedPrincipalsValue, "\n\t\r", false);
            while (st.hasMoreTokens())
            {
                String principalStr = st.nextToken();
                StringTokenizer st2 = new StringTokenizer(principalStr, ":", false);
                String principal = null; // the principal of the
                // trusted client
                Float maxDaysValid = null; // maximum lifetime of the
                // returned proxy
                if (st2.countTokens() == 1)
                {
                    principal = principalStr.trim();
                    maxDaysValid = Float.MAX_VALUE; // no limit
                }
                else if (st2.countTokens() == 2)
                {
                    principal = st2.nextToken().trim();
                    maxDaysValid = Float.parseFloat(st2.nextToken().trim());
                    if (maxDaysValid <= 0)
                    {
                        throw new IllegalArgumentException(
                                "Maximum valid days must be positive, " + maxDaysValid);
                    }
                }
                else
                {
                    throw new IllegalArgumentException(
                            "Cannot parse trusted principal from servlet config: "
                                    + principalStr);
                }
                LOGGER.info("trusted: " + principal + " , max days valid: " + maxDaysValid);
                trustedPrincipals.put(new X500Principal(principal), maxDaysValid);
            }
        }
        
        this.dataSourceName = config.getInitParameter(DSNAME);
        this.database = config.getInitParameter(CATALOG);
        this.schema = config.getInitParameter(SCHEMA);
        
        LOGGER.info("persistence: " + dataSourceName + " " + database + " " + schema);
    }

    /**
     * Handles the HTTP <code>GET</code> method.
     * 
     * @param request servlet request
     * @param response servlet response
     * @throws java.io.IOException
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws IOException
    {
        WebServiceLogInfo logInfo = new ServletLogInfo(request);
        LOGGER.info(logInfo.start());
        long start = System.currentTimeMillis();
        try
        {
            Subject subject = AuthenticationUtil.getSubject(request);
            logInfo.setSubject(subject);
            
            AuthMethod am = AuthenticationUtil.getAuthMethod(subject);
            if (am == null || AuthMethod.ANON.equals(am))
                throw new AccessControlException("permission denied");
            
            DelegationActionFactory factory = new DelegationActionFactory(
                    request, trustedPrincipals, dataSourceName, database, schema);
            DelegationAction delegationAction = factory.getDelegationAction();

            X509CertificateChain certkey;
            try
            {
                certkey = Subject.doAs(subject, delegationAction);
            }
            catch(PrivilegedActionException ex)
            {
                throw ex.getException();
            }
            
            if (certkey.getChain() == null)
            {
                throw new ResourceNotFoundException("No signed certificate");
            }

            // this is streamed directly, so there is no way to set the content length
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/x-x509-user-cert");
            ByteCountWriter out = new ByteCountWriter(new BufferedWriter(response.getWriter(), 8192));
            PEMWriter pemWriter = new PEMWriter(out);

            try
            {
                pemWriter.writeObject(certkey.getChain()[0]);
                pemWriter.writeObject(certkey.getPrivateKey());

                for (int i = 1; i < certkey.getChain().length; i++)
                {
                    pemWriter.writeObject(certkey.getChain()[i]);
                }
                pemWriter.flush();
            }
            finally
            {
                try 
                { 
                    pemWriter.close(); 
                }
                catch(IOException ex)
                {
                    // TODO
                }
     		logInfo.setBytes(out.getByteCount());
            }
        }
        catch(IllegalArgumentException ex)
        {
            logInfo.setMessage(ex.getMessage());
            logInfo.setSuccess(true);
            LOGGER.debug("invalid input", ex);
            writeError(response, HttpServletResponse.SC_BAD_REQUEST, ex.getMessage());
        }
        catch(UnsupportedOperationException ex)
        {
            logInfo.setMessage(ex.getMessage());
            logInfo.setSuccess(true);
            LOGGER.debug("unsupported", ex);
            writeError(response, HttpServletResponse.SC_NOT_IMPLEMENTED, ex.getMessage());
        }
        catch(AccessControlException ex)
        {
            logInfo.setMessage(ex.getMessage());
            logInfo.setSuccess(true);
            LOGGER.debug("unauthorized", ex);
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
        }
        catch(ResourceNotFoundException ex)
        {
            logInfo.setMessage(ex.getMessage());
            logInfo.setSuccess(true);
            LOGGER.debug("certificate not found", ex);
            writeError(response, HttpServletResponse.SC_NOT_FOUND, ex.getMessage());
        }
        catch (Throwable t)
        {
            String message = t.getMessage();
            logInfo.setMessage(message);
            logInfo.setSuccess(false);

            LOGGER.error(message, t);
            writeError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            LOGGER.info(logInfo.end());
        }
    }
    
    private void writeError(HttpServletResponse response, int code, String message)
        throws IOException
    {
        response.setContentType("text/plain");
        response.setStatus(code);
        PrintWriter pw = new PrintWriter(response.getWriter());
        pw.println(message);
        pw.flush();
        pw.close();
    }

    /**
     * OutputStream wrapper that ensures close() is not called.
     * 
     * @author majorb
     * 
     */
    private class SafeOutputStream extends FilterOutputStream
    {
        SafeOutputStream(OutputStream ostream)
        {
            super(ostream);
        }

        @Override
        public void close() throws IOException
        {
            // do nothing
        }
    }

    public Map<X500Principal, Float> getTrustedPrincipals()
    {
        
        return Collections.unmodifiableMap(trustedPrincipals);
    }
}
