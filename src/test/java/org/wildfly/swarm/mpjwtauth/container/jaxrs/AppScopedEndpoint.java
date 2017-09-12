package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Test that an attempt to inject a raw token value type into an @ApplicationScoped bean
 * generates a DeploymentException
 */
@ApplicationScoped
@RolesAllowed("Tester")
@Path("/endp")
public class AppScopedEndpoint {
    @Inject
    JsonWebToken jwt;
    @Inject
    @Claim(standard = Claims.iss)
    private String issuer;

    @GET
    @Path("/verify")
    public Response verifyInjectedIssuer(@QueryParam("iss") String iss) {
        return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
    }
}
