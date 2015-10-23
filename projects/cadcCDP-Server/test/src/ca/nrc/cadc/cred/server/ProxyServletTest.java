/*
 ************************************************************************
 ****  C A N A D I A N   A S T R O N O M Y   D A T A   C E N T R E  *****
 *
 * (c) 2011.                            (c) 2011.
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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;

import java.util.Map;

import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;

import org.junit.Test;

/**
 * Mock test of the ProxyServlet
 * @author pdowler
 */
public class ProxyServletTest
{

    @Test
    public void testInit() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid1 = new Float(30.0f);
        String expectedDN2 = "cn=test2,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid2 = new Float(0.5);
        expect(configMock.getInitParameter(ProxyServlet.TRUSTED_PRINCIPALS_PARAM))
                .andReturn((expectedDN1 + '\n' + expectedDN2 + ": " + expectedDaysValid2));
        
        expect(configMock.getInitParameter(ProxyServlet.DSNAME)).andReturn("jdbc/foo");
        expect(configMock.getInitParameter(ProxyServlet.CATALOG)).andReturn("foo");
        expect(configMock.getInitParameter(ProxyServlet.SCHEMA)).andReturn("bar");
        
        replay(configMock);

        testServlet.init(configMock);

        Map<X500Principal, Float> trustedDNs = testServlet
                .getTrustedPrincipals();

        assertEquals(expectedDaysValid1, trustedDNs
                .get(new X500Principal(expectedDN1)));
        assertEquals(expectedDaysValid2, trustedDNs
                .get(new X500Principal(expectedDN2)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testFailInit() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca";
        Float expectedDaysValid1 = new Float(-0.5);
        expect(
                configMock
                        .getInitParameter(ProxyServlet.TRUSTED_PRINCIPALS_PARAM))
                .andReturn((expectedDN1 + ":" + expectedDaysValid1));

        replay(configMock);

        testServlet.init(configMock);

    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testFailInit2() throws Exception
    {
        ProxyServlet testServlet = new ProxyServlet();
        ServletConfig configMock = createMock(ServletConfig.class);
        String expectedDN1 = "cn=test1,ou=hia.nrc.ca,o=grid,c=ca: WRONG FLOAT";
        expect(
                configMock
                        .getInitParameter(ProxyServlet.TRUSTED_PRINCIPALS_PARAM))
                .andReturn((expectedDN1));

        replay(configMock);

        testServlet.init(configMock);

    }
}
