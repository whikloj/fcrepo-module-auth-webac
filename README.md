# fcrepo-module-auth-webac

WebAC Authorization Delegate Module for the Fedora 4 Repository. This is an implementation of the W3C's proposed WebAccessControl at: [https://www.w3.org/wiki/WebAccessControl](https://www.w3.org/wiki/WebAccessControl).

[![Build Status](https://travis-ci.org/fcrepo4-labs/fcrepo-module-auth-webac.png?branch=master)](https://travis-ci.org/fcrepo4-labs/fcrepo-module-auth-webac)

This module enables an ACL based access control to the Fedora repository. Each protected resource should have an ACL file associated with it either directly or via an ancestor. The ACL file defines authorization based on three entities: 1) who has access, 2) what are the access permissions, and 3) to which resource. The ontology of the ACL RDF file can be found at: [http://www.w3.org/ns/auth/acl](http://www.w3.org/ns/auth/acl).

### Fedora 4 WebAC documentation
[https://wiki.duraspace.org/display/FEDORA4x/WebAC+Authorization+Delegate](https://wiki.duraspace.org/display/FEDORA4x/WebAC+Authorization+Delegate)

### Deployment and Configuration
The [fcrepo-webapp-plus](https://github.com/fcrepo4-exts/fcrepo-webapp-plus) provides a convenient option to build the deployable Fedora web application that is bundled with the WebAC module. Refer to the [fcrepo-webapp-plus README](https://github.com/fcrepo4-exts/fcrepo-webapp-plus/blob/master/README.md) for instructions. 

The "Example Scenarios" section in the [WebAC Authorization Delegate wiki page](https://wiki.duraspace.org/display/FEDORA4x/WebAC+Authorization+Delegate#WebACAuthorizationDelegate-ExampleScenarios) has configuration instructions for some of the common authorization scenarios.
