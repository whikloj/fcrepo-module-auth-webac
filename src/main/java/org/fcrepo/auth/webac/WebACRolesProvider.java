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

import static java.util.Collections.unmodifiableList;
import static com.hp.hpl.jena.rdf.model.ModelFactory.createDefaultModel;
import static org.apache.commons.lang3.StringUtils.substringBeforeLast;
import static org.apache.jena.riot.Lang.TTL;
import static org.fcrepo.auth.webac.URIConstants.FOAF_AGENT_VALUE;
import static org.fcrepo.auth.webac.URIConstants.FOAF_GROUP;
import static org.fcrepo.auth.webac.URIConstants.FOAF_MEMBER_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESSTO_CLASS_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESSTO_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AGENT_CLASS_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AGENT_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_AUTHORIZATION;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_MODE_VALUE;
import static org.fcrepo.auth.webac.URIConstants.WEBAC_NAMESPACE_VALUE;
import static org.fcrepo.kernel.modeshape.identifiers.NodeResourceConverter.nodeConverter;
import static org.fcrepo.kernel.modeshape.utils.FedoraTypesUtils.isNonRdfSourceDescription;
import static org.fcrepo.kernel.modeshape.utils.UncheckedFunction.uncheck;
import static org.modeshape.jcr.api.JcrConstants.JCR_CONTENT;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.File;
import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.fcrepo.auth.roles.common.AccessRolesProvider;
import org.fcrepo.http.commons.session.SessionFactory;
import org.fcrepo.kernel.api.identifiers.IdentifierConverter;
import org.fcrepo.kernel.api.models.FedoraResource;
import org.fcrepo.kernel.api.models.NonRdfSourceDescription;
import org.fcrepo.kernel.api.services.NodeService;
import org.fcrepo.kernel.modeshape.rdf.impl.DefaultIdentifierTranslator;
import org.fcrepo.kernel.modeshape.rdf.impl.PropertiesRdfContext;
import org.fcrepo.kernel.modeshape.utils.UncheckedPredicate;

import org.modeshape.jcr.value.Path;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

import com.hp.hpl.jena.graph.Triple;
import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.Property;
import com.hp.hpl.jena.rdf.model.Resource;
import com.hp.hpl.jena.shared.JenaException;

/**
 * @author acoburn
 * @since 9/3/15
 */
public class WebACRolesProvider implements AccessRolesProvider {

    public static final String ROOT_AUTHORIZATION_PROPERTY = "fcrepo.auth.webac.authorization";

    private static final Logger LOGGER = getLogger(WebACRolesProvider.class);

    private static final List<String> EMPTY = unmodifiableList(new ArrayList<>());

    private static final String FEDORA_INTERNAL_PREFIX = "info:fedora";

    private static final String ROOT_AUTHORIZATION_LOCATION = "/root-authorization.ttl";

    @Autowired
    private NodeService nodeService;

    @Autowired
    private SessionFactory sessionFactory;

    @Override
    public void postRoles(final Node node, final Map<String, Set<String>> data) throws RepositoryException {
        throw new UnsupportedOperationException("postRoles() is not implemented");
    }

    @Override
    public void deleteRoles(final Node node) throws RepositoryException {
        throw new UnsupportedOperationException("deleteRoles() is not implemented");
    }

    @Override
    public Map<String, List<String>> findRolesForPath(final Path absPath, final Session session)
            throws RepositoryException {
        return getAgentRoles(locateResource(absPath, session));
    }

    private FedoraResource locateResource(final Path path, final Session session) {

        final Predicate<Path> exists = UncheckedPredicate.uncheck(x -> session.nodeExists(x.toString()));

        if (exists.test(path) || path.isRoot()) {
            LOGGER.debug("findRolesForPath: {}", path.getString());
            return nodeService.find(session, path.toString());
        }
        LOGGER.trace("Path: {} does not exist, checking parent", path.getString());
        return locateResource(path.getParent(), session);
    }

    @Override
    public Map<String, List<String>> getRoles(final Node node, final boolean effective) {
        return getAgentRoles(nodeService.cast(node));
    }

    /**
     *  For a given FedoraResource, get a mapping of acl:agent values to acl:mode values.
     */
    private Map<String, List<String>> getAgentRoles(final FedoraResource resource) {
        LOGGER.debug("Getting agent roles for: {}", resource.getPath());

        // Get the effective ACL by searching the target node and any ancestors.
        final Optional<ACLHandle> effectiveAcl = getEffectiveAcl(
                isNonRdfSourceDescription.test(resource.getNode()) ?
                    ((NonRdfSourceDescription)nodeConverter.convert(resource.getNode())).getDescribedResource() :
                    resource);

        // Construct a list of acceptable acl:accessTo values for the target resource.
        final List<String> resourcePaths = new ArrayList<>();
        resourcePaths.add(FEDORA_INTERNAL_PREFIX + resource.getPath());

        // Construct a list of acceptable acl:accessToClass values for the target resource.
        final List<URI> rdfTypes = resource.getTypes();

        // Add the resource location and types of the ACL-bearing parent,
        // if present and if different than the target resource.
        effectiveAcl
            .map(x -> x.resource)
            .filter(x -> !x.getPath().equals(resource.getPath()))
            .ifPresent(x -> {
                resourcePaths.add(FEDORA_INTERNAL_PREFIX + x.getPath());
                rdfTypes.addAll(x.getTypes());
            });

        // If we fall through to the system/classpath-based Authorization and it
        // contains any acl:accessTo properties, it is necessary to add each ancestor
        // path up the node hierarchy, starting at the resource location up to the
        // root location. This way, the checkAccessTo predicate (below) can be properly
        // created to match any acl:accessTo values that are part of the getDefaultAuthorization.
        // This is not relevant if an effectiveAcl is present.
        if (!effectiveAcl.isPresent()) {
            resourcePaths.addAll(getAllPathAncestors(resource.getPath()));
        }

        // Create a function to check acl:accessTo, scoped to the given resourcePaths
        final Predicate<WebACAuthorization> checkAccessTo = accessTo.apply(resourcePaths);

        // Create a function to check acl:accessToClass, scoped to the given rdf:type values,
        // but transform the URIs to Strings first.
        final Predicate<WebACAuthorization> checkAccessToClass =
            accessToClass.apply(rdfTypes.stream().map(URI::toString).collect(Collectors.toList()));

        // Read the effective Acl and return a list of acl:Authorization statements
        final List<WebACAuthorization> authorizations = effectiveAcl
                .map(uncheck(x -> getAuthorizations(x.uri.toString())))
                .orElseGet(() -> getDefaultAuthorizations());

        // Filter the acl:Authorization statements so that they correspond only to statements that apply to
        // the target (or acl-bearing ancestor) resource path or rdf:type.
        // Then, assign all acceptable acl:mode values to the relevant acl:agent values: this creates a UNION
        // of acl:modes for each particular acl:agent.
        final Map<String, Set<String>> effectiveRoles = new HashMap<>();
        authorizations.stream()
            .filter(x -> checkAccessTo.test(x) || checkAccessToClass.test(x))
            .forEach(x -> {
                Stream.concat(x.getAgents().stream(), dereferenceAgentClasses(x.getAgentClasses()).stream())
                    .distinct()
                    .forEach(y -> {
                        effectiveRoles.putIfAbsent(y, new HashSet<>());
                        effectiveRoles.get(y).addAll(
                            x.getModes().stream()
                                        .map(URI::toString)
                                        .collect(Collectors.toList()));
                    });
            });

        LOGGER.debug("Unfiltered ACL: {}", effectiveRoles);

        // Transform the effectiveRoles from a Set to a List.
        return effectiveRoles.entrySet().stream()
            .map(x -> new AbstractMap.SimpleEntry<>(x.getKey(), new ArrayList<>(x.getValue())))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Given a path (e.g. /a/b/c/d) retrieve a list of all ancestor paths.
     * In this case, that would be a list of "/a/b/c", "/a/b", "/a" and "/".
     */
    private List<String> getAllPathAncestors(final String path) {
        final List<String> segments = Arrays.asList(path.split("/"));
        return IntStream.range(1, segments.size()).boxed()
                    .map(x -> FEDORA_INTERNAL_PREFIX + "/" + String.join("/", segments.subList(1, x)))
                    .collect(Collectors.toList());
    }

    /**
     *  This is a function for generating a Predicate that filters WebACAuthorizations according
     *  to whether the given acl:accessToClass values contain any of the rdf:type values provided
     *  when creating the predicate.
     */
    private final Function<List<String>, Predicate<WebACAuthorization>> accessToClass = uris -> x -> {
        return uris.stream()
                   .distinct()
                   .filter(y -> x.getAccessToClassURIs().contains(y))
                   .findFirst()
                   .isPresent();
    };

    /**
     *  This is a function for generating a Predicate that filters WebACAuthorizations according
     *  to whether the given acl:accessTo values contain any of the target resource values provided
     *  when creating the predicate.
     */
    private final Function<List<String>, Predicate<WebACAuthorization>> accessTo = uris -> x -> {
        return uris.stream()
                   .distinct()
                   .filter(y -> x.getAccessToURIs().contains(y))
                   .findFirst()
                   .isPresent();
    };

    /**
     *  This maps a Collection of acl:agentClass values to a List of agents.
     *  Any out-of-domain URIs are silently ignored.
     */
    private List<String> dereferenceAgentClasses(final Collection<String> agentClasses) {
        final Session internalSession = sessionFactory.getInternalSession();
        final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(internalSession);

        final List<String> members = new ArrayList<>();
        agentClasses.stream()
                    .distinct()
                    .forEach(x -> {
                        if (x.startsWith(FEDORA_INTERNAL_PREFIX)) {
                            final FedoraResource resource = nodeService.find(
                                internalSession, x.substring(FEDORA_INTERNAL_PREFIX.length()));
                            members.addAll(getAgentMembers(translator, resource));
                        } else if (x.equals(FOAF_AGENT_VALUE)) {
                            members.add(x);
                        } else {
                            LOGGER.info("Ignoring agentClass: {}", x);
                        }
                    });

        if (LOGGER.isDebugEnabled() && !agentClasses.isEmpty()) {
            LOGGER.debug("Found {} members in {} agentClass resources", members.size(), agentClasses.size());
        }

        return members;
    }

    /**
     *  Given a FedoraResource, return a list of agents.
     */
    private Set<String> getAgentMembers(final IdentifierConverter<Resource, FedoraResource> translator,
            final FedoraResource resource) {
        final Set<String> members = new HashSet<>();
        final Model model = createDefaultModel();

        final Predicate<Property> isMember = memberTestFromTypes.apply(resource.getTypes());

        resource.getTriples(translator, PropertiesRdfContext.class)
            .filter(p -> isMember.test(model.asStatement(p).getPredicate()))
            .forEachRemaining(t -> {
                if (t.getObject().isURI()) {
                    members.add(t.getObject().getURI());
                } else if (t.getObject().isLiteral()) {
                    members.add(t.getObject().getLiteralValue().toString());
                }
            });

        return members;
    }

    /**
     *  A simple predicate for filtering out any non-foaf:member properties
     */
    final Function<List<URI>, Predicate<Property>> memberTestFromTypes = types -> {
        final Set<URI> typeLookup = new HashSet<>(types);
        return p -> !p.isAnon() &&
            typeLookup.contains(FOAF_GROUP) && p.getURI().equals(FOAF_MEMBER_VALUE);
    };

    /**
     *  A simple predicate for filtering out any non-acl triples.
     */
    static final Predicate<Property> isAclPredicate =
         p -> !p.isAnon() && p.getNameSpace().startsWith(WEBAC_NAMESPACE_VALUE);

    /**
     *  This function reads a Fedora ACL resource and all of its acl:Authorization children.
     *  The RDF from each child resource is put into a WebACAuthorization object, and the
     *  full list is returned.
     *
     *  @param location the location of the ACL resource
     *  @return a list of acl:Authorization objects
     */
    private List<WebACAuthorization> getAuthorizations(final String location) {

        final Session internalSession = sessionFactory.getInternalSession();
        final List<WebACAuthorization> authorizations = new ArrayList<>();
        final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(internalSession);
        final Model model = createDefaultModel();

        LOGGER.debug("Effective ACL: {}", location);

        // Find the specified ACL resource

        if (location.startsWith(FEDORA_INTERNAL_PREFIX)) {

            final FedoraResource resource = nodeService.find(internalSession,
                    location.substring(FEDORA_INTERNAL_PREFIX.length()));

            // Read each child resource, filtering on acl:Authorization type, keeping only acl-prefixed triples.
            resource.getChildren().forEachRemaining(child -> {
                if (child.getTypes().contains(WEBAC_AUTHORIZATION)) {
                    final Map<String, List<String>> aclTriples = new HashMap<>();
                    child.getTriples(translator, PropertiesRdfContext.class)
                        .filter(p -> isAclPredicate.test(model.asStatement(p).getPredicate()))
                        .forEachRemaining(t -> {
                            aclTriples.putIfAbsent(t.getPredicate().getURI(), new ArrayList<>());
                            if (t.getObject().isURI()) {
                                aclTriples.get(t.getPredicate().getURI()).add(
                                    substringBeforeLast(t.getObject().getURI(), "/" + JCR_CONTENT));
                            } else if (t.getObject().isLiteral()) {
                                aclTriples.get(t.getPredicate().getURI()).add(
                                    t.getObject().getLiteralValue().toString());
                            }
                        });
                    // Create a WebACAuthorization object from the provided triples.
                    LOGGER.debug("Adding acl:Authorization from {}", child.getPath());
                    authorizations.add(createAuthorizationFromMap(aclTriples));
                }
            });
        }
        return authorizations;
    }

    private static WebACAuthorization createAuthorizationFromMap(final Map<String, List<String>> data) {
        return new WebACAuthorization(
                    data.getOrDefault(WEBAC_AGENT_VALUE, EMPTY),
                    data.getOrDefault(WEBAC_AGENT_CLASS_VALUE, EMPTY),
                    data.getOrDefault(WEBAC_MODE_VALUE, EMPTY).stream()
                                .map(URI::create).collect(Collectors.toList()),
                    data.getOrDefault(WEBAC_ACCESSTO_VALUE, EMPTY),
                    data.getOrDefault(WEBAC_ACCESSTO_CLASS_VALUE, EMPTY));
    }

    /**
     * Recursively find the effective ACL as a URI along with the FedoraResource that points to it.
     * This way, if the effective ACL is pointed to from a parent resource, the child will inherit
     * any permissions that correspond to access to that parent. This ACL resource may or may not exist,
     * and it may be external to the fedora repository.
     */
    private static Optional<ACLHandle> getEffectiveAcl(final FedoraResource resource) {
        try {
            final IdentifierConverter<Resource, FedoraResource> translator =
                new DefaultIdentifierTranslator(resource.getNode().getSession());
            final List<String> acls = new ArrayList<>();
            final Model model = createDefaultModel();

            resource.getTriples(translator, PropertiesRdfContext.class)
                .filter(t -> model.asStatement(t).getPredicate().hasURI(WEBAC_ACCESS_CONTROL_VALUE))
                .filter(t -> t.getObject().isURI())
                .forEachRemaining(t -> {
                    acls.add(t.getObject().getURI());
                });

            if (!acls.isEmpty()) {
                if (acls.size() > 1) {
                    LOGGER.warn("Found multiple ACLs defined for this node. Using: {}", acls.get(0));
                }
                return Optional.of(new ACLHandle(URI.create(acls.get(0)), resource));
            } else if (resource.getNode().getDepth() == 0) {
                LOGGER.debug("No ACLs defined on this node or in parent hierarchy");
                return Optional.empty();
            } else {
                LOGGER.trace("Checking parent resource for ACL. No ACL found at {}", resource.getPath());
                return getEffectiveAcl(resource.getContainer());
            }
        } catch (final RepositoryException ex) {
            LOGGER.debug("Exception finding effective ACL: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    private List<WebACAuthorization> getDefaultAuthorizations() {
        final Map<String, List<String>> aclTriples = new HashMap<>();
        final List<WebACAuthorization> authorizations = new ArrayList<>();

        getDefaultAcl().listStatements().forEachRemaining(x -> {
            if (isAclPredicate.test(x.getPredicate())) {
                final Triple t = x.asTriple();
                aclTriples.putIfAbsent(t.getPredicate().getURI(), new ArrayList<>());
                if (t.getObject().isURI()) {
                    aclTriples.get(t.getPredicate().getURI()).add(t.getObject().getURI());
                } else if (t.getObject().isLiteral()) {
                    aclTriples.get(t.getPredicate().getURI()).add(
                        t.getObject().getLiteralValue().toString());
                }
            }
        });

        authorizations.add(createAuthorizationFromMap(aclTriples));

        return authorizations;
    }

    private static Model getDefaultAcl() {
        final String rootAcl = System.getProperty(ROOT_AUTHORIZATION_PROPERTY);
        final Model model = createDefaultModel();

        if (rootAcl != null && new File(rootAcl).isFile()) {
            try {
                LOGGER.debug("Getting root authorization from file: {}", rootAcl);
                return model.read(rootAcl);
            } catch (final JenaException ex) {
                LOGGER.error("Error parsing root authorization file: {}", ex.getMessage());
            }
        }
        try (final InputStream is = WebACRolesProvider.class.getResourceAsStream(ROOT_AUTHORIZATION_LOCATION)) {
            LOGGER.debug("Getting root authorization from classpath: {}", ROOT_AUTHORIZATION_LOCATION);
            return model.read(is, null, TTL.getName());
        } catch (final IOException ex) {
            LOGGER.error("Error reading root authorization file: {}", ex.getMessage());
        } catch (final JenaException ex) {
            LOGGER.error("Error parsing root authorization file: {}", ex.getMessage());
        }
        return createDefaultModel();
    }
}
