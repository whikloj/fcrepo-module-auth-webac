package org.fcrepo.auth.webac;

import static com.google.common.collect.Iterators.filter;
import static org.fcrepo.kernel.modeshape.rdf.ManagedRdf.isManagedTriple;

import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.function.Predicate;

import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.api.utils.iterators.RdfStream;
import org.fcrepo.kernel.modeshape.identifiers.NamespaceConverter;
import org.fcrepo.kernel.modeshape.rdf.impl.ChildrenRdfContext;
import org.fcrepo.kernel.modeshape.rdf.impl.PrefixingIdentifierTranslator;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;
import org.fcrepo.kernel.modeshape.rdf.impl.TypeRdfContext;

import com.hp.hpl.jena.graph.Node;
import com.hp.hpl.jena.graph.NodeFactory;
import com.hp.hpl.jena.graph.Triple;
import com.hp.hpl.jena.rdf.model.Resource;

public class WebACAuthorizationImpl implements WebACAuthorization {

    final Predicate<Triple> tripleFilter = isManagedTriple.negate();

    IdentifierConverter<Resource, FedoraResource> idTranslator = null;

    RdfStream permissions = new RdfStream();

    public WebACAuthorizationImpl(final IdentifierConverter<Resource, FedoraResource> translator,
            final FedoraResource resource) {
        idTranslator = translator;
        final RdfStream childRdf = resource.getTriples(translator, ChildrenRdfContext.class);
        for (final Triple t : childRdf.iterable()) {
            permissions.concat(
                    filter(translator.convert((Resource) t.getObject()).getTriples(translator(), TypeRdfContext.class),
                            tripleFilter::test));
            permissions.concat(filter(
                    translator.convert((Resource) t.getObject()).getTriples(translator(), PropertiesRdfContext.class),
                    tripleFilter::test));
        }

    }

    @Override
    public Set<String> getAgents() {
        final Predicate<? super Triple> predicate =
                p -> p.predicateMatches(NodeFactory.createURI(URIConstants.WEBAC_AGENT_VALUE));
                return getStringSet(predicate);
    }

    @Override
    public Set<String> getAgentClasses() {
        final Predicate<? super Triple> predicate =
                p -> p.predicateMatches(NodeFactory.createURI(URIConstants.WEBAC_AGENT_CLASS_VALUE));
                return getStringSet(predicate);
    }

    @Override
    public Set<URI> getModes() {
        final Set<URI> theSet;
        final Predicate<? super Triple> predicate =
                p -> p.predicateMatches(NodeFactory.createURI(URIConstants.WEBAC_MODE_VALUE));

                final RdfStream filteredTriples = permissions.filter(predicate);
                for (final Triple t : filteredTriples) {
                    theSet.add(URI.create(t.getObject().getURI()));
                }
                return theSet;
    }

    @Override
    public Set<String> getAccessToURIs() {
        final Predicate<? super Triple> predicate =
                p -> p.predicateMatches(NodeFactory.createURI(URIConstants.WEBAC_ACCESSTO_VALUE));
                return getStringSet(predicate);
    }

    @Override
    public Set<String> getAccessToClassURIs() {
        final Predicate<? super Triple> predicate =
                p -> p.predicateMatches(NodeFactory.createURI(URIConstants.WEBAC_ACCESSTO_CLASS_VALUE));
                return getStringSet(predicate);
    }

    static public WebACAuthorizationImpl getWebACAuth(final IdentifierConverter<Resource, FedoraResource> translator,
            final FedoraResource node) {
        return new WebACAuthorizationImpl(translator, node);
    }

    private IdentifierConverter<Resource, FedoraResource> translator() {
        return idTranslator;
    }

    private Set<String> getStringSet(final Predicate<? super Triple> p) {
        final Set<String> theSet;
        final RdfStream filteredTriples = permissions.filter(p);
        for (final Triple t : filteredTriples) {
            theSet.add(t.getObject().getURI().toString());
        }
        return theSet;
    }
}
