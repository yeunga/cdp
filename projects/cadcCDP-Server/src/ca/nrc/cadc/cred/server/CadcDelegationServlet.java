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

import java.io.IOException;
import java.security.AccessControlException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.astrogrid.security.delegation.DelegationServlet;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.log.ServletLogInfo;
import ca.nrc.cadc.log.WebServiceLogInfo;

/**
 * This servlet is used in inject AccessControl information
 */
public class CadcDelegationServlet extends DelegationServlet
{
    private static final long serialVersionUID = 2740612605831268729L;
    private static Logger LOGGER = Logger.getLogger(CadcDelegationServlet.class);
    public static final String SU_DNS = "suDNs";
    private Set<X500Principal> suDNs = new HashSet<X500Principal>();

    /**
     * Read the configuration.
     */
    public void init(final ServletConfig config) 
        throws ServletException
    {
        super.init(config);
        String suDNStr = config.getInitParameter(SU_DNS);
        if (suDNStr != null)
        {
            String[] dns = suDNStr.split("\n");
            for (String dn : dns)
            {
                X500Principal su = new X500Principal(dn);
                suDNs.add(su);
                LOGGER.info("SU: " + su.getName());
            }
        }
    }

    /**
     * Determines the caller subject before passing the request to the
     * DelegationServlet.
     * 
     * @param request
     *            servlet request
     * @param response
     *            servlet response
     */
    @Override
    protected void service(final HttpServletRequest request,
            final HttpServletResponse response) throws IOException
    {
        WebServiceLogInfo logInfo = new ServletLogInfo(request);
        LOGGER.info(logInfo.start());
        long start = System.currentTimeMillis();
        try
        {
            final Subject currentSubject = createSubject(request);
            logInfo.setSubject(currentSubject);
            
            Subject.doAs(currentSubject,
                    new PrivilegedExceptionAction<Object>()
                    {
                        public Object run() throws IOException
                        {
                            handleService(request, response);
                            return null; // nothing to return
                        }
                    });
        }
        catch (Throwable t)
        {
            LOGGER.debug(t);
            if (t instanceof PrivilegedActionException)
            {
                t = ((PrivilegedActionException)t).getCause();
                LOGGER.debug(t);
            }
            
            logInfo.setMessage(t.getMessage());
            logInfo.setSuccess(false);
            
            if (t instanceof AccessControlException)
            {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().println("Unauthorized");
            }
            else if (t instanceof IllegalArgumentException)
            {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().println("Bad Request: " + t.getMessage());
            }
            else
            {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().println("Internal Error: " + t.getMessage());
            }
        }
        finally
        {
            logInfo.setElapsedTime(System.currentTimeMillis() - start);
            LOGGER.info(logInfo.end());
        }
    }

    private void handleService(HttpServletRequest request,
            HttpServletResponse response) throws IOException
    {
        super.service(request, response);
    }

    /**
     * Create a subject, and add all of the X509 Principals into it.
     * 
     * @param request
     *            The Request to create from.
     * @return An instance of a Subject.
     */
    @SuppressWarnings("unchecked")
    private Subject createSubject(final HttpServletRequest request)
    {
        X509Certificate[] ca = (X509Certificate[]) request
                .getAttribute("javax.servlet.request.X509Certificate");
        Collection<X509Certificate> certs = null;
        if (ca != null && ca.length > 0)
            certs = Arrays.asList(ca);
        // only ssl connections accepted (no remote user)

        Subject callerSubject = AuthenticationUtil.getSubject(request);
        Subject ret = callerSubject;
        
        // check whether user is superuser executing something on users
        // behalf
        String userDN = request.getParameter("DN");
        if (userDN != null)
        {
            Set<X500Principal> authPS = callerSubject.getPrincipals(X500Principal.class);
            boolean isSU = false;
            for (X500Principal caller : authPS)
            {
                for (X500Principal suDN : suDNs)
                {
                    if (AuthenticationUtil.equals(caller, suDN))
                    {
                        // super user doing something on users behalf
                        // build and return a different subject
                        isSU = true;
                    }
                    
                }
            }
            if (isSU)
            {
                X500Principal delegatedPrinc = new X500Principal(userDN);
                ret = new Subject();
                ret.getPrincipals().add(delegatedPrinc);
                LOGGER.debug("Superuser ... access on behalf of user " + userDN);
            }
            else
            {
                throw new AccessControlException("create certficate for " + userDN);
            }
        }
        
        
        return ret;
    }
}
