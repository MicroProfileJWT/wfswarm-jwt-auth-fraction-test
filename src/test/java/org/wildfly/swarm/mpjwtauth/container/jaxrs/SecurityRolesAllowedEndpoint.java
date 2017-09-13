package org.wildfly.swarm.mpjwtauth.container.jaxrs;


import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/secured-roles-allowed")
@RolesAllowed("SecurityRolesAllowedEndpointRole")
public class SecurityRolesAllowedEndpoint {
    @Inject
    private JsonWebToken jwt;

    @GET
    @Path("/inheritRolesAllowed")
    @Produces(MediaType.TEXT_PLAIN)
    public String inheritRolesAllowed() {
        return jwt.getName();
    }

    @GET
    @Path("/overrideWithDenyAll")
    @Produces(MediaType.TEXT_PLAIN)
    @DenyAll
    public String overrideWithDenyAll() {
        return jwt.getName();
    }

    @GET
    @Path("/overrideRoles")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("overrideRolesRole")
    public String overrideRoles() {
        return jwt.getName();
    }

    @GET
    @Path("/overrideWithBadRoles")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("overrideWithBadRolesRole")
    public String overrideWithBadRoles() {
        return jwt.getName();
    }

    @GET
    @Path("/overrideWithPermitAll")
    @Produces(MediaType.TEXT_PLAIN)
    @PermitAll
    public String overrideWithPermitAll() {
        return jwt.getName();
    }
}
