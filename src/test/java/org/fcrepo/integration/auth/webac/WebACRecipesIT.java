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

import java.io.File;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.fcrepo.integration.http.api.AbstractResourceIT;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.FileEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.util.EntityUtils;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;

/**
 * @author Peter Eichman
 * @author whikloj
 * @since September 4, 2015
 */
public class WebACRecipesIT extends AbstractResourceIT {

    private static Logger logger = getLogger(WebACRecipesIT.class);

    protected static final int SERVER_PORT = Integer.parseInt(System.getProperty("fcrepo.dynamic.test.port", "8080"));

    protected static final String HOSTNAME = "localhost";

    protected static final String serverAddress = "http://" + HOSTNAME + ":" + SERVER_PORT + "/rest/";

    protected final PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();

    protected static CloseableHttpClient client;

    protected final ClassLoader classLoader = getClass().getClassLoader();

    public WebACRecipesIT() {
        connectionManager.setMaxTotal(Integer.MAX_VALUE);
        connectionManager.setDefaultMaxPerRoute(20);
        connectionManager.closeIdleConnections(3, TimeUnit.SECONDS);
        client = HttpClientBuilder.create().setConnectionManager(connectionManager).build();
    }

    @Before
    public void setUp() throws ClientProtocolException, IOException {
        logger.debug("setup complete");
    }

    @Test
    public void scenario1() throws Exception {
        logger.info("Running scenario1");
        final String objA = getRandomPid();
        final HttpPut method = new HttpPut(serverAddress + "/" + objA);
        final FileEntity acl =
                new FileEntity(new File(classLoader.getResource("acls/01/acl.ttl").getFile()));
        setAuth(method, "fedoraAdmin");
        method.setHeader("Content-type", "text/turtle");
        method.setEntity(acl);
        final HttpResponse response = client.execute(method);
        final String content = EntityUtils.toString(response.getEntity());
        final int status = response.getStatusLine().getStatusCode();
        assertEquals("Didn't get a CREATED response! Got content:\n" + content,
                CREATED.getStatusCode(), status);
    }

    protected static void setAuth(final AbstractHttpMessage method, final String username) {
        final String creds = username + ":password";
        // in test configuration we don't need real passwords
        final String encCreds =
                new String(Base64.encodeBase64(creds.getBytes()));
        final String basic = "Basic " + encCreds;
        method.setHeader("Authorization", basic);
    }

    protected static String getRandomPid() {
        return UUID.randomUUID().toString();
    }
}
