/**
 * Copyright 2015 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.integration.auth.webac;

import static javax.ws.rs.core.Response.Status.CREATED;
import static org.junit.Assert.assertEquals;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.fcrepo.kernel.api.RdfLexicon.DC_NAMESPACE;

import java.io.IOException;
import java.io.InputStream;
import org.fcrepo.integration.http.api.AbstractResourceIT;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Peter Eichman
 * @author whikloj
 * @since September 4, 2015
 */
public class WebACRecipesIT extends AbstractResourceIT {

    private static final Logger logger = LoggerFactory.getLogger(WebACRecipesIT.class);

    private static final String DC_TITLE = DC_NAMESPACE + "title";

    /**
     * Convenience method to create an ACL with 0 or more authorization resources in the respository.
     */
    private String ingestAcl(final String username, final String aclResourcePath,
            final String... authorizationResourcePaths) throws IOException {

        // create the ACL
        final HttpResponse aclResponse = ingestTurtleResource(username, aclResourcePath, "/rest");

        // get the URI to the newly created resource
        final String aclURI = aclResponse.getFirstHeader("Location").getValue();

        // add all the authorizations
        for (final String authorizationResourcePath : authorizationResourcePaths) {
            ingestTurtleResource(username, authorizationResourcePath, aclURI.replace(serverAddress, ""));
        }

        return aclURI;
    }

    /**
     * Convenience method to POST the contents of a Turtle file to the repository to create a new resource. Returns
     * the HTTP response from that request. Throws an IOException if the server responds with anything other than a
     * 201 Created response code.
     */
    private HttpResponse ingestTurtleResource(final String username, final String path, final String requestURI)
            throws IOException {
        final HttpPost request = postObjMethod(requestURI);

        logger.debug("POST to {} to create {}", requestURI, path);

        setAuth(request, username);

        final InputStream file = this.getClass().getResourceAsStream(path);
        final InputStreamEntity fileEntity = new InputStreamEntity(file);
        request.setEntity(fileEntity);
        request.setHeader("Content-Type", "text/turtle;charset=UTF-8");

        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals("Didn't get a CREATED response!", CREATED.getStatusCode(), getStatus(response));
            return response;
        }

    }

    /**
     * Convenience method to set up a regular FedoraResource
     *
     * @param path Path to put the resource under
     * @return the Location of the newly created resource
     * @throws IOException
     */
    private String ingestObj(final String path) throws IOException {
        final HttpPut request = putObjMethod(path.replace(serverAddress, ""));
        setAuth(request, "fedoraAdmin");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
            return response.getFirstHeader("Location").getValue();
        }
    }

    private String ingestDatastream(final String path, final String ds) throws IOException {
        final HttpPut request = putDSMethod(path, ds, "some not so random content");
        setAuth(request, "fedoraAdmin");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
            return response.getFirstHeader("Location").getValue();
        }
    }

    /**
     * Convenience method to link a Resource to a WebACL resource
     *
     * @param protectedResource path of the resource to be protected by the
     * @param aclResource path of the Acl resource
     */
    private void linkToAcl(final String protectedResource, final String aclResource)
            throws IOException {
        final HttpPatch request = patchObjMethod(protectedResource.replace(serverAddress, ""));
        setAuth(request, "fedoraAdmin");
        request.setHeader("Content-type", "application/sparql-update");
        request.setEntity(new StringEntity(
                "INSERT { <> <" + WEBAC_ACCESS_CONTROL_VALUE + "> <" + aclResource + "> . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, response.getStatusLine().getStatusCode());
        }
    }

    /**
     * Convenience method for applying credentials to a request
     *
     * @param method the request to add the credentials to
     * @param username the username to add
     */
    private static void setAuth(final AbstractHttpMessage method, final String username) {
        final String creds = username + ":password";
        final String encCreds = new String(Base64.encodeBase64(creds.getBytes()));
        final String basic = "Basic " + encCreds;
        method.setHeader("Authorization", basic);
    }

    @Test
    public void scenario1() throws IOException {
        final String testObj = ingestObj("/rest/webacl_box1");
        final String acl1 = ingestAcl("fedoraAdmin", "/acls/01/acl.ttl", "/acls/01/authorization.ttl");
        linkToAcl(testObj, acl1);

        logger.debug("Anonymous can't read");
        final HttpGet request = getObjMethod(testObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Can username 'smith123' read " + testObj);
        setAuth(request, "smith123");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void scenario2() throws IOException {
        final String id = "/rest/box/bag/collection";
        final String testObj = ingestObj(id);
        final String acl2 = ingestAcl("fedoraAdmin", "/acls/02/acl.ttl", "/acls/02/authorization.ttl");
        linkToAcl(testObj, acl2);

        logger.debug("Anonymous can not read " + testObj);
        final HttpGet requestGet = getObjMethod(id);
        try (final CloseableHttpResponse response = execute(requestGet)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("GroupId 'Editors' can read " + testObj);
        final HttpGet requestGet2 = getObjMethod(id);
        setAuth(requestGet2, "jones");
        requestGet2.setHeader("some-header", "Editors");
        try (final CloseableHttpResponse response = execute(requestGet2)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous cannot write " + testObj);
        final HttpPatch requestPatch = patchObjMethod(id);
        requestPatch.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Test title\" . } WHERE {}"));
        requestPatch.setHeader("Content-type", "application/sparql-update");
        try (final CloseableHttpResponse response = execute(requestPatch)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Editors can write " + testObj);
        final HttpPatch requestPatch2 = patchObjMethod(id);
        setAuth(requestPatch2, "jones");
        requestPatch2.setHeader("some-header", "Editors");
        requestPatch2.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Different title\" . } WHERE {}"));
        requestPatch2.setHeader("Content-type", "application/sparql-update");
        try (final CloseableHttpResponse response = execute(requestPatch2)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }

    }

    @Test
    public void scenario3() throws IOException {
        final String idDark = "/rest/dark/archive";
        final String idLight = "/rest/dark/archive/sunshine";
        final String testObj = ingestObj(idDark);
        final String testObj2 = ingestObj(idLight);
        final String acl3 =
                ingestAcl("fedoraAdmin", "/acls/03/acl.ttl", "/acls/03/auth_open.ttl", "/acls/03/auth_restricted.ttl");
        linkToAcl(testObj, acl3);

        logger.debug("Anonymous can't read " + testObj);
        final HttpGet requestGet = getObjMethod(idDark);
        try (final CloseableHttpResponse response = execute(requestGet)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Restricted can read " + testObj);
        final HttpGet requestGet2 = getObjMethod(idDark);
        setAuth(requestGet2, "jones");
        requestGet2.setHeader("some-header", "Restricted");
        try (final CloseableHttpResponse response = execute(requestGet2)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can read " + testObj2);
        final HttpGet requestGet3 = getObjMethod(idLight);
        try (final CloseableHttpResponse response = execute(requestGet3)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Restricted can read " + testObj2);
        final HttpGet requestGet4 = getObjMethod(idLight);
        setAuth(requestGet4, "jones");
        requestGet4.setHeader("some-header", "Restricted");
        try (final CloseableHttpResponse response = execute(requestGet4)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void scenario4() throws IOException {
        final String id = "/rest/public_collection";
        final String testObj = ingestObj(id);
        final String acl4 = ingestAcl("fedoraAdmin", "/acls/04/acl.ttl", "/acls/04/auth1.ttl", "/acls/04/auth2.ttl");
        linkToAcl(testObj, acl4);

        logger.debug("Anonymous can read " + testObj);
        final HttpGet requestGet = getObjMethod(id);
        try (final CloseableHttpResponse response = execute(requestGet)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Editors can read " + testObj);
        final HttpGet requestGet2 = getObjMethod(id);
        setAuth(requestGet2, "jones");
        requestGet2.setHeader("some-header", "Editors");
        try (final CloseableHttpResponse response = execute(requestGet2)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Smith can access " + testObj);
        final HttpGet requestGet3 = getObjMethod(id);
        setAuth(requestGet3, "smith");
        try (final CloseableHttpResponse response = execute(requestGet3)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can't write " + testObj);
        final HttpPatch requestPatch = patchObjMethod(id);
        requestPatch.setHeader("Content-type", "application/sparql-update");
        requestPatch.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Change title\" . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(requestPatch)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Editors can write " + testObj);
        final HttpPatch requestPatch2 = patchObjMethod(id);
        requestPatch2.setHeader("Content-type", "application/sparql-update");
        requestPatch2.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"New title\" . } WHERE {}"));
        setAuth(requestPatch2, "jones");
        requestPatch2.setHeader("some-header", "Editors");
        try (final CloseableHttpResponse response = execute(requestPatch2)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }

        logger.debug("Smith can't write " + testObj);
        final HttpPatch requestPatch3 = patchObjMethod(id);
        requestPatch3.setHeader("Content-type", "application/sparql-update");
        requestPatch3.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Different title\" . } WHERE {}"));
        setAuth(requestPatch3, "smith");
        try (final CloseableHttpResponse response = execute(requestPatch3)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

    }

    @Test
    public void scenario5() throws IOException {
        final String idPublic = "/rest/mixedCollection/publicObj";
        final String idPrivate = "/rest/mixedCollection/privateObj";
        final String testObj = ingestObj("/rest/mixedCollection");
        final String publicObj = ingestObj(idPublic);
        final HttpPatch patch = patchObjMethod(idPublic);
        final String acl5 =
                ingestAcl("fedoraAdmin", "/acls/05/acl.ttl", "/acls/05/auth_open.ttl", "/acls/05/auth_restricted.ttl");
        linkToAcl(testObj, acl5);

        setAuth(patch, "fedoraAdmin");
        patch.setHeader("Content-type", "application/sparql-update");
        patch.setEntity(new StringEntity("INSERT { <> a <http://example.com/terms#publicImage> . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }
        final String privateObj = ingestObj(idPrivate);

        logger.debug("Anonymous can see eg:publicImage " + publicObj);
        final HttpGet requestGet = getObjMethod(idPublic);
        try (final CloseableHttpResponse response = execute(requestGet)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can't see other resource " + privateObj);
        final HttpGet requestGet2 = getObjMethod(idPrivate);
        try (final CloseableHttpResponse response = execute(requestGet2)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Admins can see eg:publicImage " + publicObj);
        final HttpGet requestGet3 = getObjMethod(idPublic);
        setAuth(requestGet3, "jones");
        requestGet3.setHeader("some-header", "Admins");
        try (final CloseableHttpResponse response = execute(requestGet3)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Admins can see others" + privateObj);
        final HttpGet requestGet4 = getObjMethod(idPrivate);
        setAuth(requestGet4, "jones");
        requestGet4.setHeader("some-header", "Admins");
        try (final CloseableHttpResponse response = execute(requestGet4)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void scenario9() throws IOException {
        final String idPublic = "/rest/anotherCollection/publicObj";
        final String groups = "/rest/group";
        final String fooGroup = groups + "/foo";
        final String testObj = ingestObj("/rest/anotherCollection");
        final String publicObj = ingestObj(idPublic);

        final HttpPut request = putObjMethod(fooGroup);
        setAuth(request, "fedoraAdmin");

        final InputStream file = this.getClass().getResourceAsStream("/acls/09/group.ttl");
        final InputStreamEntity fileEntity = new InputStreamEntity(file);
        request.setEntity(fileEntity);
        request.setHeader("Content-Type", "text/turtle;charset=UTF-8");

        assertEquals("Didn't get a CREATED response!", CREATED.getStatusCode(), getStatus(request));

        final String acl9 = ingestAcl("fedoraAdmin", "/acls/09/acl.ttl", "/acls/09/authorization.ttl");
        linkToAcl(testObj, acl9);

        logger.debug("Person1 can see object " + publicObj);
        final HttpGet requestGet1 = getObjMethod(idPublic);
        setAuth(requestGet1, "person1");
        assertEquals(HttpStatus.SC_OK, getStatus(requestGet1));

        logger.debug("Person2 can see object " + publicObj);
        final HttpGet requestGet2 = getObjMethod(idPublic);
        setAuth(requestGet2, "person2");
        assertEquals(HttpStatus.SC_OK, getStatus(requestGet2));

        logger.debug("Person3 user cannot see object " + publicObj);
        final HttpGet requestGet3 = getObjMethod(idPublic);
        setAuth(requestGet3, "person3");
        assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(requestGet3));
    }

    @Test
    public void testAccessToRoot() throws IOException {
        final String id = "/rest/" + getRandomUniqueId();
        final String testObj = ingestObj(id);
        final String acl = ingestAcl("fedoraAdmin", "/acls/06/acl.ttl", "/acls/06/authorization.ttl");

        // Add ACL to root
        linkToAcl("/rest/", acl);

        logger.debug("Anonymous can't read");
        final HttpGet request = getObjMethod(id);
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Can username 'smith123' read {}", testObj);
        final HttpGet requestGet1 = getObjMethod(id);
        setAuth(requestGet1, "smith123");
        try (final CloseableHttpResponse response = execute(requestGet1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    @Ignore("FAILING")
    public void testAccessToBinary() throws IOException {
        // Block access to "book"
        final String idBook = "/rest/book";
        ingestObj(idBook);

        // Open access datastream, "file"
        final String id = idBook + "/file";
        final String testObj = ingestDatastream(idBook, "file");
        final String acl = ingestAcl("fedoraAdmin",
                "/acls/07/acl.ttl",
                "/acls/07/authorization.ttl",
                "/acls/07/authorization-book.ttl");

        linkToAcl(idBook, acl);

        logger.debug("Anonymous can't read");
        final HttpGet request = getObjMethod(id);
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Can username 'smith123' read {}", testObj);
        final HttpGet requestGet1 = getObjMethod(id);
        setAuth(requestGet1, "smith123");
        try (final CloseableHttpResponse response = execute(requestGet1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    @Ignore("FAILING")
    public void testAccessToHashResource() throws IOException {
        final String id = "/rest/some/parent#hash-resource";
        final String testObj = ingestObj(id);
        final String acl = ingestAcl("fedoraAdmin", "/acls/08/acl.ttl", "/acls/08/authorization.ttl");
        linkToAcl(testObj, acl);

        logger.debug("Anonymous can't read");
        final HttpGet request = getObjMethod(id);
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Can username 'smith123' read {}", testObj);
        final HttpGet requestGet1 = getObjMethod(id);
        setAuth(requestGet1, "smith123");
        try (final CloseableHttpResponse response = execute(requestGet1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void testAccessToVersionedResources() throws IOException {
        final String idVersion = "/rest/versionResource";
        ingestObj(idVersion);

        final HttpPatch patch1 = patchObjMethod(idVersion);
        setAuth(patch1, "fedoraAdmin");
        patch1.addHeader("Content-type", "application/sparql-update");
        patch1.setEntity(
                new StringEntity("PREFIX pcdm: <http://pcdm.org/models#> INSERT { <> a pcdm:Object } WHERE {}"));
        try (final CloseableHttpResponse response = execute(patch1)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }

        final String acl = ingestAcl("fedoraAdmin",
                "/acls/10/acl.ttl",
                "/acls/10/authorization.ttl");

        linkToAcl(idVersion, acl);

        final HttpGet requestGet1 = getObjMethod(idVersion);
        setAuth(requestGet1, "testuser");
        try (final CloseableHttpResponse response = execute(requestGet1)) {
            assertEquals("testuser can't read object", HttpStatus.SC_OK, getStatus(response));
        }

        final HttpPost requestPost1 = postObjMethod(idVersion + "/fcr:versions");
        requestPost1.addHeader("Slug", "v0");
        setAuth(requestPost1, "fedoraAdmin");
        try (final CloseableHttpResponse response = execute(requestPost1)) {
            assertEquals("Unable to create a new version", HttpStatus.SC_CREATED, getStatus(response));
        }

        final HttpGet requestGet2 = getObjMethod(idVersion);
        setAuth(requestGet2, "testuser");
        try (final CloseableHttpResponse response = execute(requestGet2)) {
            assertEquals("testuser can't read versioned object", HttpStatus.SC_OK, getStatus(response));
        }
    }

}
