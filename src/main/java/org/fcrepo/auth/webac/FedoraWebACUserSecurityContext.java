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

import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_APPEND_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_CONTROL_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_READ_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_WRITE_VALUE;

import java.security.Principal;

import org.fcrepo.auth.common.FedoraAuthorizationDelegate;
import org.fcrepo.auth.common.FedoraUserSecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The security context for Fedora WebAC servlet users. These users are not
 * necessarily authenticated by the container, i.e. users may include the
 * general public. This security context delegates all access decisions to the
 * configured authorization delegate.
 *
 * @author mohideen
 */
public class FedoraWebACUserSecurityContext extends FedoraUserSecurityContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(FedoraWebACUserSecurityContext.class);

    /**
     * Constructs a new security context.
     *
     * @param userPrincipal the user principal associated with this security context
     * @param fad the authorization delegate
     */
    protected FedoraWebACUserSecurityContext(final Principal userPrincipal,
                                             final FedoraAuthorizationDelegate fad) {
        super(userPrincipal, fad);
    }

    /**
     * {@inheritDoc}
     *
     * @see org.modeshape.jcr.security.SecurityContext#hasRole(String)
     */
    @Override
    public final boolean hasRole(final String roleName) {
        LOGGER.debug("Checking hasRole({})", roleName);

        if (WEBAC_MODE_READ_VALUE.equals(roleName)) {
            return true;
        } else if (WEBAC_MODE_WRITE_VALUE.equals(roleName)) {
            return true;
        } else if (WEBAC_MODE_APPEND_VALUE.equals(roleName)) {
            return true;
        } else if (WEBAC_MODE_CONTROL_VALUE.equals(roleName)) {
            return true;
        }
        return false;
    }

}
