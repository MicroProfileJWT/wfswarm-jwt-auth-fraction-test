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

@Path("/secured-permit-all")
@PermitAll
public class SecurityPermitAllEndpoint {
    @Inject
    private JsonWebToken jwt;

    @GET
    @Path("/inheritPermitAll")
    @Produces(MediaType.TEXT_PLAIN)
    public String inheritPermitAll() {
        return jwt.getName();
    }

    @GET
    @Path("/overridePermitAllWithDenyAll")
    @Produces(MediaType.TEXT_PLAIN)
    @DenyAll
    public String overridePermitAllWithDenyAll() {
        return jwt.getName();
    }

    @GET
    @Path("/overridePermitAllWithRoles")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("overridePermitAllWithRolesRole")
    public String overridePermitAllWithRoles() {
        return jwt.getName();
    }
    @GET
    @Path("/overridePermitAllWithBadRoles")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("overridePermitAllWithBadRolesRole")
    public String overridePermitAllWithBadRoles() {
        return jwt.getName();
    }
}
