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
import static org.slf4j.LoggerFactory.getLogger;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AUTHORIZATION_VALUE;
import static org.fcrepo.integration.auth.webac.WebACUtilities.addWebACACL;
import static org.fcrepo.integration.auth.webac.WebACUtilities.wrapURIs;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.fcrepo.auth.roles.basic.integration.BasicRolesAdminIT;
import org.fcrepo.auth.roles.common.integration.RolesFadTestObjectBean;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.junit.Test;
import org.slf4j.Logger;

/**
 * @author whikloj
 */
public class BasicRolesAdminWebACIT extends BasicRolesAdminIT {

    private static Logger LOGGER = getLogger(BasicRolesAdminWebACIT.class);

    protected final static List<RolesFadTestObjectBean> test_objs =
            org.fcrepo.integration.auth.webac.WebACUtilities.defineTestObjects();

    private static String ACL_PATH = "acl_resource";

    private static String AUTHORIZATION_PATH = "auth1";
    /**
     * This test is good for running individually to find bootstrap problems with the delegate. All it does is build the
     * Fedora XACML environment.
     */
    @Test
    public void test() {
        LOGGER.debug("Spring startup was successfull.");
    }


    @Override
    protected void addObjectACLs(
            final RolesFadTestObjectBean obj)
                    throws Exception {
        LOGGER.debug("Adding acls ({}) for {}", obj.getACLs().size(), obj.getPath());
        if (obj.getACLs().size() > 0) {
            final HttpPut method = putObjMethod(obj.getPath() + "/" + ACL_PATH);
            setAuth(method, "fedoraAdmin");
            method.addHeader("Content-type", "text/turtle");
            method.setEntity(addWebACACL(obj.getPath() + "/acl_resource", method));
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" + content,
                    CREATED.getStatusCode(), status);

            addObjectAuthorizations(obj.getPath() + "/" + ACL_PATH + "/" + AUTHORIZATION_PATH, obj.getACLs());
        }
    }

    private void addObjectAuthorizations(final String path, final List<Map<String, String>> acls) throws Exception {
        final String patch = "<> a " + wrapURIs(WEBAC_AUTHORIZATION_VALUE);
        for (final Map<String, String> m : acls) {
            for (final Entry<String, String> entry : m.entrySet()) {
                patch.concat(" ; " + wrapURIs(entry.getKey().toString()) + " " + wrapURIs(entry.getValue().toString()));
            }
        }
        patch.concat(" .");
        final HttpPut method = putObjMethod(path);
        method.addHeader("Content-type", "text/turtle");
        final StringEntity acl = new StringEntity(patch);
        method.setEntity(acl);
        setAuth(method, "fedoraAdmin");
        final HttpResponse response = client.execute(method);
        final String content = EntityUtils.toString(response.getEntity());
        final int status = response.getStatusLine().getStatusCode();
        assertEquals("Didn't get a CREATED response! Got content:\n" + content,
                CREATED.getStatusCode(), status);
    }

    @Override
    protected void addDatastreamACLs(
            final RolesFadTestObjectBean obj,
            final String dsid) throws Exception {
        if (obj.getDatastreamACLs(dsid) != null) {
            final String aclPath = obj.getPath() + "/" + ACL_PATH;
            final String authzPath = aclPath + "/" + AUTHORIZATION_PATH;
            final HttpPut method = putObjMethod(aclPath);
            setAuth(method, "fedoraAdmin");
            method.addHeader("Content-type", "text/turtle");
            method.setEntity(addWebACACL(aclPath, method));
            final HttpResponse response = client.execute(method);
            final String content = EntityUtils.toString(response.getEntity());
            final int status = response.getStatusLine().getStatusCode();
            assertEquals("Didn't get a CREATED response! Got content:\n" + content,
                    CREATED.getStatusCode(), status);

            addObjectAuthorizations(authzPath, obj.getDatastreamACLs(dsid));
        }
    }
}
