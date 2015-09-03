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
package org.fcrepo.auth.webac;

import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_READ_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_WRITE_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_APPEND_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_CONTROL_VALUE;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;

import org.fcrepo.auth.common.FedoraAuthorizationDelegate;
import org.fcrepo.auth.common.FedoraUserSecurityContext;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * @author mohideen
 * @since 9/1/15.
 */
@RunWith(MockitoJUnitRunner.class)
public class FedoraWebACUserSecurityContextTest {

    @Mock
    private FedoraAuthorizationDelegate fad;
    @Mock
    private Principal principal;
    @Mock
    private HttpServletRequest request;

    @Test
    public void testHasRole() {
        final FedoraUserSecurityContext context = new FedoraWebACUserSecurityContext(this.principal, this.fad);
        Assert.assertTrue(context.hasRole(WEBAC_MODE_READ_VALUE));
        Assert.assertTrue(context.hasRole(WEBAC_MODE_WRITE_VALUE));
        Assert.assertTrue(context.hasRole(WEBAC_MODE_APPEND_VALUE));
        Assert.assertTrue(context.hasRole(WEBAC_MODE_CONTROL_VALUE));
        Assert.assertFalse(context.hasRole(null));
        Assert.assertFalse(context.hasRole("other"));
    }

}
