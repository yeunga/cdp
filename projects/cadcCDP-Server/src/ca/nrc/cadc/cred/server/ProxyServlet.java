/*
************************************************************************
*******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
**************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
*
*  (c) 2011.                            (c) 2011.
*  Government of Canada                 Gouvernement du Canada
*  National Research Council            Conseil national de recherches
*  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
*  All rights reserved                  Tous droits réservés
*
*  NRC disclaims any warranties,        Le CNRC dénie toute garantie
*  expressed, implied, or               énoncée, implicite ou légale,
*  statutory, of any kind with          de quelque nature que ce
*  respect to the software,             soit, concernant le logiciel,
*  including without limitation         y compris sans restriction
*  any warranty of merchantability      toute garantie de valeur
*  or fitness for a particular          marchande ou de pertinence
*  purpose. NRC shall not be            pour un usage particulier.
*  liable in any event for any          Le CNRC ne pourra en aucun cas
*  damages, whether direct or           être tenu responsable de tout
*  indirect, special or general,        dommage, direct ou indirect,
*  consequential or incidental,         particulier ou général,
*  arising from the use of the          accessoire ou fortuit, résultant
*  software.  Neither the name          de l'utilisation du logiciel. Ni
*  of the National Research             le nom du Conseil National de
*  Council of Canada nor the            Recherches du Canada ni les noms
*  names of its contributors may        de ses  participants ne peuvent
*  be used to endorse or promote        être utilisés pour approuver ou
*  products derived from this           promouvoir les produits dérivés
*  software without specific prior      de ce logiciel sans autorisation
*  written permission.                  préalable et particulière
*                                       par écrit.
*
*  This file is part of the             Ce fichier fait partie du projet
*  OpenCADC project.                    OpenCADC.
*
*  OpenCADC is free software:           OpenCADC est un logiciel libre ;
*  you can redistribute it and/or       vous pouvez le redistribuer ou le
*  modify it under the terms of         modifier suivant les termes de
*  the GNU Affero General Public        la “GNU Affero General Public
*  License as published by the          License” telle que publiée
*  Free Software Foundation,            par la Free Software Foundation
*  either version 3 of the              : soit la version 3 de cette
*  License, or (at your option)         licence, soit (à votre gré)
*  any later version.                   toute version ultérieure.
*
*  OpenCADC is distributed in the       OpenCADC est distribué
*  hope that it will be useful,         dans l’espoir qu’il vous
*  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
*  without even the implied             GARANTIE : sans même la garantie
*  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
*  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
*  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
*  General Public License for           Générale Publique GNU Affero
*  more details.                        pour plus de détails.
*
*  You should have received             Vous devriez avoir reçu une
*  a copy of the GNU Affero             copie de la Licence Générale
*  General Public License along         Publique GNU Affero avec
*  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
*  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
*                                       <http://www.gnu.org/licenses/>.
*
*  $Revision: 5 $
*
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
                    maxDaysValid = 30.0f;
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
