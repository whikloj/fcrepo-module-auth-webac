package org.fcrepo.auth.webac;

import static com.google.common.collect.Iterators.filter;
import static org.fcrepo.kernel.modeshape.rdf.ManagedRdf.isManagedTriple;

import java.net.URI;
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
import com.hp.hpl.jena.graph.Triple;
import com.hp.hpl.jena.rdf.model.Resource;

public class WebACAuthorizationImpl implements WebACAuthorization {

    final Predicate<Triple> tripleFilter = isManagedTriple.negate();

    IdentifierConverter<Resource, FedoraResource> idTranslator = null;

    RdfStream permissions;

    public WebACAuthorizationImpl(final IdentifierConverter<Resource, FedoraResource> translator,
            final FedoraResource resource) {
        idTranslator = translator;
        final RdfStream childRdf = resource.getTriples(translator, ChildrenRdfContext.class);
        permissions = new RdfStream();
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
        return Collections.checkedSet(permissions.filter()
    }

    @Override
    public Set<String> getAgentClasses() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<URI> getModes() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<String> getAccessToURIs() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<String> getAccessToClassURIs() {
        // TODO Auto-generated method stub
        return null;
    }

    static public WebACAuthorizationImpl getWebACAuth(final IdentifierConverter<Resource, FedoraResource> translator,
            final FedoraResource node) {
        return new WebACAuthorizationImpl(translator, node);
    }

    private IdentifierConverter<Resource, FedoraResource> translator() {
        return idTranslator;
    }
}
