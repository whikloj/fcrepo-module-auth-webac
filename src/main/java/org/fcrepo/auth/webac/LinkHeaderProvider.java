/*
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

import static com.hp.hpl.jena.rdf.model.ModelFactory.createDefaultModel;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.slf4j.LoggerFactory.getLogger;

import java.net.URI;
import java.util.Optional;

import javax.jcr.Session;
import javax.ws.rs.core.Link;
import javax.ws.rs.core.UriInfo;

import org.fcrepo.http.commons.api.UriAwareHttpHeaderFactory;
import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.api.services.NodeService;
import org.fcrepo.kernel.modeshape.rdf.impl.DefaultIdentifierTranslator;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Multimap;
import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.Resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Insert WebAC Link headers to responses
 *
 * @author whikloj
 * @since 2015-10-30
 */
@Component
public class LinkHeaderProvider implements UriAwareHttpHeaderFactory {

    private static final Logger LOGGER = getLogger(LinkHeaderProvider.class);

    @Autowired
    private SessionFactory sessionFactory;

    @Autowired
    private NodeService nodeService;

    @Override
    public Multimap<String, String> createHttpHeadersForResource(final UriInfo uriInfo, final FedoraResource resource) {

        final Session internalSession = sessionFactory.getInternalSession();
        final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(internalSession);
        final Model model = createDefaultModel();
        final ListMultimap<String, String> headers = ArrayListMultimap.create();

        LOGGER.debug("Adding WebAC Link Header for Resource: {}", resource);
        // Get the correct Acl for this resource
        final Optional<Pair<URI, FedoraResource>> acls = WebACRolesProvider.getEffectiveAcl(resource);
        if (acls.isPresent()) {
            // If the Acl is present we probably need to use the internal session to get it's URI
            nodeService.find(internalSession, acls.get().getRight().getPath())
                    .getTriples(translator, PropertiesRdfContext.class)
                    .filter(t -> model.asStatement(t).getPredicate().hasURI(WEBAC_ACCESS_CONTROL_VALUE))
                    .filter(t -> t.getObject().isURI())
                    .forEachRemaining(t -> {
                headers.put("Link", Link.fromUri(uriInfo.getBaseUriBuilder()
                        .path(translator.convert(model.asStatement(t).getObject().asResource()).getPath())
                        .toString()).rel("acl").build().toString());
                    });
        }

        return headers;
    }


}
