/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2016.                            (c) 2016.
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
 *
 ************************************************************************
 */

package ca.nrc.cadc.web;


import ca.nrc.cadc.auth.AuthMethod;
import ca.nrc.cadc.net.HttpPost;
import ca.nrc.cadc.reg.Standards;
import ca.nrc.cadc.reg.client.LocalAuthority;
import ca.nrc.cadc.reg.client.RegistryClient;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


public class AccessControlClient
{
    private final RegistryClient registryClient;
    private final URI loginURI;


    public AccessControlClient() throws IllegalArgumentException
    {
        this(new LocalAuthority().getServiceURI(
                Standards.UMS_LOGIN_01.toString()), new RegistryClient());
    }

    /**
     * Complete constructor.
     *
     * @param serviceURI            The Service URI.
     * @param registryClient        The Registry client for lookups.*/
    AccessControlClient(final URI serviceURI,
                        final RegistryClient registryClient)
    {
        this.registryClient = registryClient;
        this.loginURI = serviceURI;
    }


    private URL lookupLoginURL()
    {
        return registryClient.getServiceURL(loginURI, Standards.UMS_LOGIN_01,
                                            AuthMethod.ANON);
    }

    /**
     * Perform a username/password verification and return the cookie value.
     *
     * @param username      The username.
     * @param password      The password char array.
     * @return              String cookie value.
     */
    public String login(final String username, final char[] password)
    {
        final OutputStream out = new ByteArrayOutputStream();
        final Map<String, Object> payload = new HashMap<>();

        payload.put("username", username);
        payload.put("password", new String(password));

        final int responseCode = post(payload, out);

        if (responseCode == 200)
        {
            return out.toString();
        }
        else
        {
            throw new IllegalArgumentException(
                    String.format("Unable to login '%s' due to Error %d.",
                                  username, responseCode));
        }
    }

    /**
     * Post the output.
     *
     * @param payload       The payload to send.
     * @param out           The stream for any output.
     * @return              Int response code.
     */
    int post(final Map<String, Object> payload, final OutputStream out)
    {
        final HttpPost post = new HttpPost(lookupLoginURL(), payload, out);

        post.run();

        return post.getResponseCode();
    }
}
