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

import static com.hp.hpl.jena.rdf.model.ModelFactory.createDefaultModel;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.slf4j.LoggerFactory.getLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.jcr.Session;
import javax.servlet.http.HttpServletResponse;
import org.fcrepo.http.commons.api.UriAwareHttpHeaderFactory;
import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.modeshape.rdf.impl.DefaultIdentifierTranslator;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;

import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.Resource;

/**
 * Insert WebAC Link headers to responses
 *
 * @author whikloj
 * @since 2015-10-30
 */
public class LinkHeaderProvider implements UriAwareHttpHeaderFactory {

    private static final Logger LOGGER = getLogger(LinkHeaderProvider.class);

    @Override
    public Optional<List<Pair<String, String>>> createHttpHeadersForResource(final HttpServletResponse servletResponse,
            final FedoraResource resource, final Session session) {
        final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(session);
        final List<Pair<String, String>> acls = new ArrayList<>();
        final Model model = createDefaultModel();

        LOGGER.debug("Inside LinkHeaderProvider");

        resource.getTriples(translator, PropertiesRdfContext.class)
        .filter(t -> model.asStatement(t).getPredicate().hasURI(WEBAC_ACCESS_CONTROL_VALUE))
        .filter(t -> t.getObject().isURI())
        .forEachRemaining(t -> {
                    acls.add(Pair.of("Link", t.getObject().getURI() + "; rel=acl"));
        });
        if (acls.size() > 0) {
            return Optional.of(acls);
        } else {
            return Optional.empty();
        }
    }


}
