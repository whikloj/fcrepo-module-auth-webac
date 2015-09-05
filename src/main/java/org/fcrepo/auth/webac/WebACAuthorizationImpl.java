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

import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author acoburn
 * @since 9/2/15
 */
public class WebACAuthorizationImpl implements WebACAuthorization {

    private final Set<String> agents = new HashSet<>();

    private final Set<String> agentClasses = new HashSet<>();

    private final Set<URI> modes = new HashSet<>();

    private final Set<String> accessTo = new HashSet<>();

    private final Set<String> accessToClass = new HashSet<>();

    /**
     * Constructor
     *
     * @param agents The acl:agent values
     * @param agentClasses the acl:agentClass values
     * @param modes the acl:mode values
     * @param accessTo the acl:accessTo values
     * @param accessToClass the acl:accessToClass values
     */
    public WebACAuthorizationImpl(final Collection<String> agents, final Collection<String> agentClasses,
            final Collection<URI> modes, final Collection<String> accessTo, final Collection<String> accessToClass) {
        this.agents.addAll(agents);
        this.agentClasses.addAll(agentClasses);
        this.modes.addAll(modes);
        this.accessTo.addAll(accessTo);
        this.accessToClass.addAll(accessToClass);
    }

    @Override
    public Set<String> getAgents() {
        return agents;
    }

    @Override
    public Set<String> getAgentClasses() {
        return agentClasses;
    }

    @Override
    public Set<URI> getModes() {
        return modes;
    }

    @Override
    public Set<String> getAccessToURIs() {
        return accessTo;
    }

    @Override
    public Set<String> getAccessToClassURIs() {
        return accessToClass;
    }
}
