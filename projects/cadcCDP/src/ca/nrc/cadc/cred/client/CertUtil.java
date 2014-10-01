
package ca.nrc.cadc.cred.client;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;
import java.util.TimeZone;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import ca.nrc.cadc.auth.X509CertificateChain;

/**
 * Utilities for certificate operations
 */
public class CertUtil
{

    /**
     * Method that generates an X509 proxy certificate
     * 
     * @param csr
     *            CSR for the certificate
     * @param lifetime
     *            lifetime of the certificate in SECONDS
     * @param chain
     *            certificate used to sign the proxy certificate
     * @return generated proxy certificate
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CertificateParsingException
     * @throws CertificateEncodingException
     * @throws SignatureException
     * @throws CertificateNotYetValidException
     * @throws CertificateExpiredException
     */
    public static X509Certificate generateCertificate(
            PKCS10CertificationRequest csr, int lifetime,
            X509CertificateChain chain) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException,
            CertificateParsingException, CertificateEncodingException,
            SignatureException, CertificateExpiredException,
            CertificateNotYetValidException
    {
        X509Certificate issuerCert = chain.getChain()[0];
        PrivateKey issuerKey = chain.getPrivateKey();

        Security.addProvider(new BouncyCastleProvider());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System
                .currentTimeMillis()));
        certGen.setIssuerDN(issuerCert.getSubjectX500Principal());

        // generate the proxy DN as the issuerDN + CN=random number
        Random rand = new Random();
        String issuerDN = issuerCert.getSubjectX500Principal().getName(
                X500Principal.RFC2253);
        String delegDN = String.valueOf(Math.abs(rand.nextInt()));
        String proxyDn = "CN=" + delegDN + "," + issuerDN;
        certGen.setSubjectDN(new X500Principal(proxyDn));

        // set validity
        GregorianCalendar date = new GregorianCalendar(TimeZone
                .getTimeZone("GMT"));
        // Start date. Allow for a sixty five minute clock skew here.
        date.add(Calendar.MINUTE, -65);
        Date beforeDate = date.getTime();
        for (X509Certificate currentCert : chain.getChain())
        {
            if (beforeDate.before(currentCert.getNotBefore()))
            {
                beforeDate = currentCert.getNotBefore();
            }
        }
        certGen.setNotBefore(beforeDate);

        // End date.
        // If hours = 0, then cert lifetime is set to that of user cert
        if (lifetime <= 0)
        {
            // set the validity of certificates as the minimum
            // of the certificates in the chain
            Date afterDate = issuerCert.getNotAfter();
            for (X509Certificate currentCert : chain.getChain())
            {
                if (afterDate.after(currentCert.getNotAfter()))
                {
                    afterDate = currentCert.getNotAfter();
                }
            }
            certGen.setNotAfter(afterDate);
        }
        else
        {
            // check the validity of the signing certificate
            date.add(Calendar.MINUTE, 5);
            date.add(Calendar.SECOND, lifetime);
            for (X509Certificate currentCert : chain.getChain())
            {
                currentCert.checkValidity(date.getTime());
            }

            certGen.setNotAfter(date.getTime());
        }

        certGen.setPublicKey(csr.getPublicKey());
        certGen.setSignatureAlgorithm(issuerCert.getSigAlgName());

        // extensions
        // add ProxyCertInfo extension to the new cert

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
                false, new AuthorityKeyIdentifierStructure(issuerCert));

        certGen.addExtension(X509Extensions.SubjectKeyIdentifier,

        false, new SubjectKeyIdentifierStructure(csr.getPublicKey("BC")));

        certGen.addExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));

        // add the Proxy Certificate Information
        // I expect this code to be removed once support to proxy
        // certificates is provided in Bouncy Castle.

        // create a proxy policy
        // types of proxy certificate policies - see RFC3820
        // impersonates the user
        final DERObjectIdentifier IMPERSONATION = new DERObjectIdentifier(
                "1.3.6.1.5.5.7.21.1");
        // independent
        // final DERObjectIdentifier INDEPENDENT = new
        // DERObjectIdentifier(
        // "1.3.6.1.5.5.7.21.2");
        // defined by a policy language
        // final DERObjectIdentifier LIMITED = new DERObjectIdentifier(
        // "1.3.6.1.4.1.3536.1.1.1.9");

        ASN1EncodableVector policy = new ASN1EncodableVector();
        policy.add(IMPERSONATION);

        // pathLengthConstr (RFC3820)
        // The pCPathLenConstraint field, if present, specifies the
        // maximum
        // depth of the path of Proxy Certificates that can be signed by
        // this
        // Proxy Certificate. A pCPathLenConstraint of 0 means that this
        // certificate MUST NOT be used to sign a Proxy Certificate. If
        // the
        // pCPathLenConstraint field is not present then the maximum proxy
        // path
        // length is unlimited. End entity certificates have unlimited
        // maximum
        // proxy path lengths.
        // DERInteger pathLengthConstr = new DERInteger(100);

        // create the proxy certificate information
        ASN1EncodableVector vec = new ASN1EncodableVector();
        // policy.add(pathLengthConstr);
        vec.add(new DERSequence(policy));

        // OID
        final DERObjectIdentifier OID = new DERObjectIdentifier(
                "1.3.6.1.5.5.7.1.14");
        certGen.addExtension(OID, true, new DERSequence(vec));

        return certGen.generate(issuerKey, "BC");
    }

    /**
     * @param chain certificate
     * @param writer writer use to write the generated PEM certificate
     * @throws IOException
     */
    public static void writePEMCertificateAndKey(
            X509CertificateChain chain, Writer writer)
            throws IOException
    {
        if (chain == null)
            throw new IllegalArgumentException("Null certificate chain");
        if (writer == null)
            throw new IllegalArgumentException("Null writer");

        PEMWriter pemWriter = new PEMWriter(writer);
        // write the first certificate first
        pemWriter.writeObject(chain.getChain()[0]);
        // then the key
        pemWriter.writeObject(chain.getPrivateKey());
        // and finally the rest of the certificates in the chain
        for (int i = 1; i < chain.getChain().length; i++)
        {
            pemWriter.writeObject(chain.getChain()[i]);
        }        
        pemWriter.flush();
    }
}
