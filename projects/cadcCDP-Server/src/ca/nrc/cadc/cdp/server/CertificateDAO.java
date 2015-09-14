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
 * @version $Revision: $
 * 
 * 
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 ************************************************************************
 */

package ca.nrc.cadc.cdp.server;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Types;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;

import org.apache.log4j.Logger;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SingleColumnRowMapper;

import ca.nrc.cadc.auth.AuthenticationUtil;
import ca.nrc.cadc.auth.SSLUtil;
import ca.nrc.cadc.auth.X509CertificateChain;
import ca.nrc.cadc.db.DBUtil;
import ca.nrc.cadc.profiler.Profiler;
import ca.nrc.cadc.vosi.avail.CheckDataSource;
import ca.nrc.cadc.vosi.avail.CheckResource;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import javax.naming.NamingException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Sybase implementation of CertificateDAO.
 * 
 * @author pdowler
 *
 */
public class CertificateDAO
{
    private static Logger logger = Logger.getLogger(CertificateDAO.class);

    private String certTable;

    private String dataSourceName = "jdbc/sybase";
    private DataSource dataSource;
    
    // TODO: make these configurable
    private String database = "archive";
    private String schema = "dbo";
    private String table = "x509_certificates";

    public CertificateDAO()
    {
        try
        {
            this.dataSource = DBUtil.getDataSource(dataSourceName);
        }
        catch(NamingException ex)
        {
            throw new RuntimeException("CONFIG: failed to find DataSource " + dataSourceName);
        }
        this.certTable = database + "." + schema + "." + table;
    }
    
    // for tests
    CertificateDAO(DataSource dataSource, String db, String schema)
    {
        this.dataSource = dataSource;
        this.database = db;
        this.schema = schema;
        this.certTable = database + "." + schema + "." + table;
    }

    public CheckResource getCheckResource()
    {
        String sql = "select top 1 hash_dn from " + certTable;
        return new CheckDataSource(dataSource, sql);
    }

    public void put(X509CertificateChain chain)
    {
        Profiler profiler = new Profiler(this.getClass());
        String hashKey = chain.getHashKey();
        String canonDn = AuthenticationUtil.canonizeDistinguishedName(chain.getPrincipal().getName());
        Date expDate = chain.getExpiryDate();
        String certChainStr = chain.certificateString();
        byte[] bytesPrivateKey = chain.getPrivateKey().getEncoded();
        //TODO just for testing - padded with zeros
        byte[] testBytesPrivateKey = Arrays.copyOf(bytesPrivateKey, bytesPrivateKey.length+1);
        testBytesPrivateKey[testBytesPrivateKey.length-1]=1;
        String csr = chain.getCsrString();
        
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        if (recordExists(hashKey))
        {
            String sql = "update " + this.certTable
                    + " set canon_dn = ?, exp_date = ?, cert_chain = ?, private_key = ?, csr = ? where hash_dn=?";
            Object[] args = new Object[] { canonDn, expDate, certChainStr, testBytesPrivateKey, csr, hashKey };
            int[] argTypes = new int[] { Types.VARCHAR, Types.TIMESTAMP, Types.VARCHAR, Types.VARBINARY, Types.VARCHAR, Types.VARCHAR };
            jdbc.update(sql, args, argTypes);
        }
        else
        {
            String sql = "insert into " + this.certTable
                + " (canon_dn, exp_date, cert_chain, private_key, csr, hash_dn) values (?,?,?,?,?,?)";
            Object[] args = new Object[] { canonDn, expDate, certChainStr, testBytesPrivateKey, csr, hashKey };
            int[] argTypes = 
                new int[] { Types.VARCHAR, Types.TIMESTAMP, Types.VARCHAR, Types.VARBINARY, Types.VARCHAR, Types.VARCHAR };

            jdbc.update(sql, args, argTypes);
        }
        profiler.checkpoint("put");
    }

    public X509CertificateChain get(X500Principal principal)
    {
        if (principal == null) return null;
        String canonizedDn = AuthenticationUtil.canonizeDistinguishedName(principal.getName());
        X500Principal p = new X500Principal(canonizedDn);
        String hashKey = Integer.toString(p.hashCode());
        return get(hashKey);
    }

    public X509CertificateChain get(String hashKey)
    {
        Profiler profiler = new Profiler(this.getClass());
        X509CertificateChain x509CertificateChain = null;

        String query = "select canon_dn, exp_date, cert_chain, private_key, csr from " + this.certTable + " where hash_dn = ? ";

        
        try
        {
            JdbcTemplate jdbc = new JdbcTemplate(dataSource);
            Map<String, Object> map = jdbc.queryForMap(query, new String[] { hashKey });
            String canonDn = (String) map.get("canon_dn");
            Date expDate = (Date) map.get("exp_date");
            String certChainStr = (String) map.get("cert_chain");
            byte[] bytesPrivateKey = (byte[]) map.get("private_key");
            
            // Sybase trims the trailing 0's of a varbinary. To compensate we add 0's to the 
            // privateKey byte array. Extra bytes in the private key array are ignored
            // when the key is built so the added 0's are only used when needed.
            // ad 20/07/2011
            bytesPrivateKey = Arrays.copyOf(bytesPrivateKey, bytesPrivateKey.length+10);
            
            String csrStr = (String) map.get("csr");

            PrivateKey privateKey = SSLUtil.readPrivateKey(bytesPrivateKey);
            X500Principal principal = new X500Principal(canonDn);

            if (certChainStr != null)
            {
                byte[] bytesCertChain = certChainStr.getBytes();
                X509Certificate[] certs = SSLUtil.readCertificateChain(bytesCertChain);

                x509CertificateChain = new X509CertificateChain(Arrays.asList(certs));
            }
            else
            {
                x509CertificateChain = new X509CertificateChain(principal, privateKey, csrStr);
            }
            x509CertificateChain.setCsrString(csrStr);
            x509CertificateChain.setExpiryDate(expDate);
            x509CertificateChain.setHashKey(hashKey);
            x509CertificateChain.setKey(privateKey);
            x509CertificateChain.setPrincipal(principal);
        }
        catch (EmptyResultDataAccessException e)
        {
            // Record not exists.
            return null;
        }
        catch(InvalidKeySpecException ex)
        {
            throw new RuntimeException("BUG: failed to read private key", ex);
        }
        catch(NoSuchAlgorithmException ex)
        {
            throw new RuntimeException("BUG: failed to read private key", ex);
        }
        catch(CertificateException ex)
        {
            throw new RuntimeException("BUG: failed to read certficate chain", ex);
        }
        catch(IOException ex)
        {
            throw new RuntimeException("BUG: failed to read certificate chain", ex);
        }
        profiler.checkpoint("get");
        return x509CertificateChain;
    }

    /* (non-Javadoc)
     * @see ca.nrc.cadc.accesscontrol.dao.CertificateDAO#delete(java.lang.String)
     */
    public void delete(String hashKey)
    {
        Profiler profiler = new Profiler(this.getClass());
        String sql = "delete from " + this.certTable + " where hash_dn = ? ";
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.update(sql, new String[] { hashKey });
        profiler.checkpoint("delete");
    }

    private boolean recordExists(String hashKey)
    {
        RowMapper rowMapper = new SingleColumnRowMapper(String.class);
        String query = "select canon_dn from " + this.certTable + " where hash_dn = ? ";
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        List<String> dnList = jdbc.query(query, new String[] { hashKey }, rowMapper);
        return (dnList != null && dnList.size() == 1);
    }

    public List<String> getAllHashKeys()
    {
        Profiler profiler = new Profiler(this.getClass());
        String query = "select hash_dn from " + this.certTable;
        RowMapper rowMapper = new SingleColumnRowMapper(String.class);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        List<String> hashKeyList = jdbc.query(query, rowMapper);
        profiler.checkpoint("getAllHashKeys");
        return hashKeyList;
    }


}
