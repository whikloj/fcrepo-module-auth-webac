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

import static org.fcrepo.auth.webac.URIConstants.FOAF_AGENT_VALUE;

import java.security.Principal;
import java.util.Set;

import javax.jcr.Session;

//import org.fcrepo.auth.common.FedoraUserSecurityContext;
import org.fcrepo.auth.roles.common.AbstractRolesAuthorizationDelegate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authorization Delegate responsible for resolving Fedora's permissions using Web Access Control (WebAC) access
 * control lists.
 *
 * @author Peter Eichman
 * @since Aug 24, 2015
 */
public class WebACAuthorizationDelegate extends AbstractRolesAuthorizationDelegate {

    /**
     * Class-level logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(WebACAuthorizationDelegate.class);

    /**
     * The security principal for every request, that represents the foaf:Agent agent class that is used to designate
     * "everyone".
     */
    private static final Principal EVERYONE = new Principal() {

        @Override
        public String getName() {
            return FOAF_AGENT_VALUE;
        }

        @Override
        public String toString() {
            return getName();
        }

    };

    @Override
    public boolean rolesHavePermission(final Session userSession, final String absPath,
            final String[] actions, final Set<String> roles) {
        final boolean permit = false;
        LOGGER.debug("Request for actions: {}, on path: {}, with roles: {}. Permission={}",
                actions,
                absPath,
                roles,
                permit);

        return permit;
    }

    @Override
    public Principal getEveryonePrincipal() {
        return EVERYONE;
    }

    //@Override
    //public FedoraUserSecurityContext getFedoraUserSecurityContext(final Principal userPrincipal) {
        //return new FedoraWebACUserSecurityContext(userPrincipal, this);
    //}

}
