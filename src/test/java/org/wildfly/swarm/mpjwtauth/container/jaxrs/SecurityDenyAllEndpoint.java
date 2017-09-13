package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import java.util.Date;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/secured-deny-all")
@DenyAll
public class SecurityDenyAllEndpoint {

    @Inject
    private JsonWebToken jwt;

    @GET
    @Path("/permitAllEndpoint")
    @PermitAll
    public String permitAllEndpoint() {
        return "Heartbeat: "+ new Date(System.currentTimeMillis()).toString();
    }

    @Path("/findWidget/{id}")
    @RolesAllowed("findWidgetRole")
    public SecuredWidget findWidget(@PathParam("id") String id) {
        return new SecuredWidget(id);
    }

    @GET
    @Path("/multipleRoles")
    @RolesAllowed({"multipleRoles1", "multipleRoles2"})
    @Produces(MediaType.TEXT_PLAIN)
    public String multipleRoles(@QueryParam("queryParam") String queryParam) {
        return "multipleRoles-"+queryParam;
    }

    @GET
    @Path("noSlash")
    @RolesAllowed("noSlashRole")
    @Produces(MediaType.TEXT_PLAIN)
    public String noSlash(@QueryParam("queryParam") String queryParam) {
        return "noSlashRole-"+queryParam;
    }

    @GET
    @Path("/denyAll")
    @Produces(MediaType.TEXT_PLAIN)
    public String denyAll() {
        return "Heartbeat: "+ new Date(System.currentTimeMillis()).toString();
    }

    @GET
    @Path("/inheritDenyAll")
    @Produces(MediaType.TEXT_PLAIN)
    public String inheritDenyAll() {
        return jwt.getName();
    }
}

