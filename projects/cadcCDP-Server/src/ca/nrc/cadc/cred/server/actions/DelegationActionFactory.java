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
 * @author majorb
 * 
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.cred.server.actions;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.DelegationToken;
import ca.nrc.cadc.auth.HttpPrincipal;
import ca.nrc.cadc.auth.PrincipalExtractor;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.server.CertificateDAO;
import ca.nrc.cadc.cred.server.ResourceNotFoundException;
import ca.nrc.cadc.profiler.Profiler;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.log4j.Logger;

/**
 * Class used to construct the appropriate delegation action.
 * 
 */
public class DelegationActionFactory
{
    private static final Logger log = Logger.getLogger(DelegationActionFactory.class);
    
    // The HTTP Servlet request
    private HttpServletRequest request;

    // The set of trusted principals
    private Map<X500Principal, Float> trustedPrincipals;
    
    private String dataSource;
    private String catalog;
    private String schema;

    /**
     * Factory constructor.
     * 
     * @param request
     * @param trustedPrincipals
     * @param dataSource
     * @param catalog
     * @param schema
     */
    public DelegationActionFactory(HttpServletRequest request, Map<X500Principal, Float> trustedPrincipals,
        String dataSource, String catalog, String schema)
    {
        this.request = request;
        if ((trustedPrincipals == null) || trustedPrincipals.isEmpty())
        {
            throw new IllegalArgumentException("Null or empty trusted principals");
        }
        this.trustedPrincipals = trustedPrincipals;
        this.dataSource = dataSource;
        this.catalog = catalog;
        this.schema = schema;
    }

    private CertificateDAO getDAO()
    {
        CertificateDAO.CertificateSchema config = new CertificateDAO.CertificateSchema(dataSource, catalog, schema);
        return new CertificateDAO(config);
    }
    
    /**
     * @return 
     * Return the appropriate delegation action for this request.
     */
    public DelegationAction getDelegationAction()
    {
        Float daysValid = null;
        X500Principal target = null;
        
        // parameter for daysValid (compatibile with the old ProxyCertServlet)
        String daysValidStr = request.getParameter("daysValid");
        if (daysValidStr != null)
        {
            try
            {
                daysValid = new Float(daysValidStr);
                if (daysValid < 0.0)
                    throw new IllegalArgumentException("invalid daysValid param:"
                        + daysValidStr + " expected: number > 0.0");
            }
            catch (NumberFormatException ex)
            {
                throw new IllegalArgumentException("invalid daysValid param:"
                        + daysValidStr + " expected: number > 0.0");
            }
        }
        
        String resource = request.getPathInfo();
        if (resource != null)
        {
            // TODO: switch to the ?idType= pattern instead of hiding it in the path
            
            // not sure why whitespaces are not decode properly
            resource = resource.replace("+", " ");
            if (resource.startsWith("/"))
                resource = resource.substring(1);

            String[] pathElements = resource.split("/");

            if (pathElements.length > 2)
            {
                return new NotFoundAction(null, trustedPrincipals);
            }

            if (pathElements[0].equalsIgnoreCase("dn"))
            {
                log.debug("GetProxyCertByDN: " + pathElements[1]);
                target = new X500Principal(pathElements[1]);
            }
            else if (pathElements[0].equalsIgnoreCase("userid"))
            {
                log.debug("GetProxyCertByUserid: " + pathElements[1]);
                try
                {
                    target = getX500FromUserID(pathElements[1]);
                }
                catch(ResourceNotFoundException ex)
                {
                    return new NotFoundAction(null, trustedPrincipals);
                }
            }
        }
        
        // target could be null
        return new GetProxyCertByDN(target, daysValid,  trustedPrincipals, getDAO());
    }
    
    protected X500Principal getX500FromUserID(final String userid)
        throws ResourceNotFoundException
    {
        Profiler profiler = new Profiler(DelegationActionFactory.class);
        // create subject with specified userid and augment with other identities
        Subject s = AuthenticationUtil.getSubject(new PrincipalExtractor()
        {
            public Set<Principal> getPrincipals()
            {
                Set<Principal> ps = new HashSet<Principal>();
                ps.add(new HttpPrincipal(userid));
                return ps;
            }

            public X509CertificateChain getCertificateChain()
            {
                return null;
            }

            public DelegationToken getDelegationToken()
            {
                return null;
            }
        });
        log.debug("augmented: " + s);
        profiler.checkpoint("getUser");
        
        Set<X500Principal> xp = s.getPrincipals(X500Principal.class);
        if (xp != null && !xp.isEmpty())
        {
            X500Principal p = xp.iterator().next();
            return p;
        }
        throw new ResourceNotFoundException("user not found: " + userid);
    }

    /**
     * Action indicating that a resource could not be found.
     */
    static final class NotFoundAction extends DelegationAction
    {

        public NotFoundAction(X500Principal name,
                Map<X500Principal, Float> trustedPrincipals)
        {
            super(name, Float.MIN_VALUE, trustedPrincipals, null);
        }

        @Override
        public X509CertificateChain getCertificate(X500Principal name)
                throws Exception
        {
            throw new ResourceNotFoundException();
        }

    }

    /**
     * Action indicating that a request is not currently supported.
     */
    static final class UnsupportedOperationAction extends
            DelegationAction
    {

        public UnsupportedOperationAction(X500Principal name,
                Map<X500Principal, Float> trustedPrincipals)
        {
            super(name, Float.MIN_VALUE, trustedPrincipals, null);
        }

        @Override
        public X509CertificateChain getCertificate(X500Principal name)
                throws Exception
        {
            throw new UnsupportedOperationException();
        }

    }

}
