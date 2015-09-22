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

import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedExceptionAction;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.cred.server.ResourceNotFoundException;
import ca.nrc.cadc.cred.CertUtil;
import ca.nrc.cadc.cred.server.CertificateDAO;
import ca.nrc.cadc.profiler.Profiler;
import java.util.Iterator;
import org.apache.log4j.Logger;

/**
 * Class encapsulating a delegation action. Concrete subclasses must
 * implement the method <code>getCertificate(String name)</code>
 * 
 */
public abstract class DelegationAction implements
        PrivilegedExceptionAction<X509CertificateChain>
{
    private static final Logger log = Logger.getLogger(DelegationAction.class);

    // The name to lookup
    X500Principal name;
    Float daysValid; // requested lifetime of the proxy

    // The set of trusted principals that are allowed to perform
    // delegation actions
    Map<X500Principal, Float> trustedPrincipals;
    
    protected CertificateDAO certDAO;
    
    Profiler profiler = new Profiler(this.getClass());

    /**
     * Delegation action constructor.
     * 
     * @param name
     *            The name to lookup
     * @param daysValid
     * @param trustedPrincipals
     *            The set of trusted principals that are allowed to
     *            perform delegation actions
     * @param certDAO
     */
    protected DelegationAction(X500Principal name, Float daysValid, Map<X500Principal, Float> trustedPrincipals,
        CertificateDAO certDAO)
    {
        this.name = name;
        this.daysValid = daysValid;
        this.trustedPrincipals = trustedPrincipals;
        this.certDAO = certDAO;
    }

    /**
     * Perform the delegation action and return the PEM string of
     * certificate and private key
     * 
     * @param name
     *            The name to lookup.
     * @return The file representing the certificate.
     * @throws Exception
     *             If an error occurs.
     */
    public abstract X509CertificateChain getCertificate(X500Principal name)
            throws Exception;

    /**
     * Entry point for delegation actions. Before
     * <code>getCertificate()</code> is called, a security check is done
     * to make sure the caller is allowed to perform delegation actions.
     * @return 
     * @throws java.lang.Exception
     */
    public X509CertificateChain run() throws Exception
    {
        AccessControlContext acContext = AccessController.getContext();
        Subject subject = Subject.getSubject(acContext);
        Set<X500Principal> principals = subject.getPrincipals(X500Principal.class);
        if (principals.isEmpty())
        {
            throw new AccessControlException(
                    "Delegation failed because the caller is not authenticated.");
        }
        else if (principals.size() > 1)
        {
            throw new AccessControlException(
                    "Delegation failed because caller autheticated with multiple certificates.");
        }

        if (this.daysValid == null)
            this.daysValid = 30.0f; // was default in ProxyCertServlet
            
        // check if it's a trusted client
        boolean authorized = false;
        X500Principal caller = principals.iterator().next();
        if (name == null || AuthenticationUtil.equals(name, caller))
        {
            authorized = true;
            if (daysValid > 30.0)
                throw new ResourceNotFoundException("Requested lifetime limitted to 30");
        }
        else
        {
            Iterator<X500Principal> xi = trustedPrincipals.keySet().iterator();
            while ( !authorized && xi.hasNext() )
            {
                X500Principal trustedPrinc = xi.next();
                if (AuthenticationUtil.equals(caller, trustedPrinc))
                {
                    authorized = true;

                    // Time to determine the allowed lifetime of certificate
                    float maxDaysValid = trustedPrincipals.get(trustedPrinc);
                    if (maxDaysValid < daysValid)
                        throw new ResourceNotFoundException("Requested lifetime limitted to " + maxDaysValid);

                    if (daysValid == 0)
                        daysValid = maxDaysValid;
                }
            }
        }
        
        if (!authorized)
        {
            throw new AccessControlException("Delegation failed because caller is not trusted.");
        }
        
        if (name == null)
        {
            log.debug("calling getCertficate(caller)");
            return getCertificate(caller);
        }
        log.debug("calling getCertficate(target)");
        return getCertificate(name);
    }

    /**
     * 
     * @return the requested lifetime of the proxy certificate
     */
    public float getDaysValid()
    {
        return daysValid;
    }

    X509CertificateChain prepareCert(X509CertificateChain signCert)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException,
            CertificateParsingException, CertificateEncodingException,
            CertificateExpiredException, CertificateNotYetValidException
    {
        log.debug("prepareCert - START");
        if (!(signCert.getPrivateKey() instanceof RSAKey))
        {
            // TODO - Only RSA keys are supported. Generate a proxy cert
            // if this is not the case
            // This should probably be cached somehow
            if (daysValid == Float.MAX_VALUE)
            {
                daysValid = 30.0f;
            }
        }
        
        if (daysValid == Float.MAX_VALUE)
        {
            // return the stored certificate as it is
            log.debug("daysValid = " + daysValid + ", returning bare certificate");
            return signCert;
        }
        else
        {
            // return proxy certificate signed with the key of the
            // stored certificate
            
            try
            {

                // Add the Bouncy Castle JCE provider. This allows the CSR
                // classes to work. The BC implementation of PKCS#10 depends
                // on the ciphers in the BC provider.
                if (Security.getProvider("BC") == null)
                {
                    Security.addProvider(new BouncyCastleProvider());
                }
    
                KeyPairGenerator keyPairGenerator = null;
                try
                {
                    keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                }
                catch (NoSuchAlgorithmException ex)
                {
                    ex.printStackTrace();
                    throw new RuntimeException(
                            "The JCE doesn't do RSA! Game over.");
                }
                keyPairGenerator.initialize(CertUtil.DEFAULT_KEY_LENGTH);
    
                // generate the subject
                String subject = signCert.getChain()[0]
                        .getSubjectX500Principal().getName(
                                X500Principal.CANONICAL);
    
                // generated the key pair
                KeyPair keys = keyPairGenerator.generateKeyPair();
    
                // generate the CSR
                PKCS10CertificationRequest csr = new PKCS10CertificationRequest(
                        CertUtil.DEFAULT_SIGNATURE_ALGORITHM, new X509Name(subject),
                        keys.getPublic(), null, keys.getPrivate(), "BC");
                log.debug("PKCS10CertificationRequest " + csr.getSignatureAlgorithm().toString());
                
                // sign the CSR
                X509Certificate newCert = CertUtil.generateCertificate(csr,
                        Math.round(daysValid * 24 * 60 * 60), signCert);
    
                // package and return
                X509Certificate[] certChain = new X509Certificate[signCert
                        .getChain().length + 1];
                certChain[0] = newCert;
                System.arraycopy(signCert.getChain(), 0, certChain, 1,
                        signCert.getChain().length);
                X509CertificateChain result = new X509CertificateChain(certChain,
                        keys.getPrivate());
                result.setPrincipal(signCert.getPrincipal());
                
                return result;
            }
            finally
            {
                profiler.checkpoint("prepareCert");
            }
        }
    }

}
