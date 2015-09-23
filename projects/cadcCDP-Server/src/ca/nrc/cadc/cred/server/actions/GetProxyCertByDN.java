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

import java.util.Map;

import javax.security.auth.x500.X500Principal;

import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.server.CertificateDAO;
import ca.nrc.cadc.net.ResourceNotFoundException;
import ca.nrc.cadc.profiler.Profiler;

/**
 * Delegation action to get a signed certificate chain given the
 * end-user's X500 distinguished name.
 */
public class GetProxyCertByDN extends DelegationAction
{
    /**
     * Constructor.
     * 
     * @param name
     * @param daysValid
     * @param trustedPrincipals
     * @param dao
     */
    public GetProxyCertByDN(X500Principal name, Float daysValid,
            Map<X500Principal, Float> trustedPrincipals, CertificateDAO dao)
    {
        super(name, daysValid, trustedPrincipals, dao);
    }

    

    /**
     * Perform the action by loading PEM String of Certificates and
     * Private Key from DB.
     * @param p
     * @return 
     * @throws ca.nrc.cadc.cred.server.ResourceNotFoundException 
     */
    @Override
    public X509CertificateChain getCertificate(X500Principal p)
        throws ResourceNotFoundException, 
            Exception // plethora of certificate exceptions
    {
        Profiler profiler = new Profiler(this.getClass());
        X509CertificateChain cert = certDAO.get(p);
        profiler.checkpoint("getCertificate");
        if (cert == null)
            throw new ResourceNotFoundException("not found: " + p.getName());
        return prepareCert(cert);
    }

}
