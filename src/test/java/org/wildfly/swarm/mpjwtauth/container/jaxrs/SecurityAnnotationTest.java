package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

/**
 * Test a variety of @RolesAllowed, @PermitAll, @DenyAll uses
 */
public class SecurityAnnotationTest extends Arquillian {
    private static String token;
    // Time claims in the token
    private static Long iatClaim;
    private static Long authTimeClaim;
    private static Long expClaim;

    @ArquillianResource
    private URL baseURL;

    @Deployment(testable=true)
    public static WebArchive createDeployment() throws IOException {
        System.setProperty("swarm.resolver.offline", "true");
        //System.setProperty("swarm.debug.port", "8888");
        //System.setProperty("swarm.logging", "DEBUG");

        URL publicKey = ClaimValueInjectionTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "SecurityAnnotationTest.war")
                .addAsResource(publicKey, "/publicKey.pem")
                .addAsManifestResource(publicKey, "/MP-JWT-SIGNER")
                .addAsResource("project-defaults.yml", "/project-defaults.yml")
                .addAsResource("logging.properties", "/logging.properties")
                .addClass(SecurityDenyAllEndpoint.class)
                .addClass(SecurityPermitAllEndpoint.class)
                .addClass(SecurityRolesAllowedEndpoint.class)
                .addClass(SecuredWidget.class)
                .addClass(SecuredApp.class)
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
                //.addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/SecuredToken.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());
    }

// SecurityDenyAllEndpoint tests
    @RunAsClient
    @Test(description = "Verify that the injected token issuer claim is as expected")
    public void findWidget() throws Exception {
        Reporter.log("Begin findWidget");
        String uri = baseURL.toExternalForm() + "/app/secured-deny-all/findWidget/100";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iss.name(), TCKConstants.TEST_ISSUER)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

    @RunAsClient
    @Test(description = "Validate a request without an MP-JWT to unsecured endpoint has HTTP_OK with expected response")
    public void permitAllEndpoint() throws Exception {
        Reporter.log("permitAllEndpoint, expect HTTP_OK");
        String uri = baseURL.toExternalForm() + "/app/secured-deny-all/permitAllEndpoint";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Assert.assertTrue(reply.startsWith("Heartbeat:"), "Saw Heartbeat: ...");
    }

    @RunAsClient
    @Test(description = "Verify that a mapped role succeeds")
    public void multipleRoles() throws Exception {
        Reporter.log("Begin multipleRoles");
        String uri = baseURL.toExternalForm() + "/app/secured-deny-all/multipleRoles";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

    @RunAsClient
    @Test(description = "Verify that relative path has valid security constraint")
    public void noSlash() throws Exception {
        Reporter.log("Begin multipleRoles");
        String uri = baseURL.toExternalForm() + "/app/secured-deny-all/noSlash";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("queryParam", "noSlashParam")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

    @RunAsClient
    @Test(description = "Verify that a token without a mapped role fails")
    public void multipleRolesFail() throws Exception {
        Reporter.log("Begin multipleRolesFail");
        String badToken = TokenUtils.generateTokenString("/FailedToken.json");

        String uri = baseURL.toExternalForm() + "/app/secured-deny-all/multipleRoles";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + badToken).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

    @RunAsClient
    @Test(description = "Verify that a method covered by DenyAll is denied")
    public void denyAll() throws Exception {
        Reporter.log("Begin denyAll");
        String uri = baseURL.toExternalForm() + "app/secured-deny-all/denyAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

    @RunAsClient
    @Test(description = "Verify that a method covered by inherited DenyAll is denied")
    public void inheritDenyAll() throws Exception {
        Reporter.log("Begin denyAll");
        String uri = baseURL.toExternalForm() + "app/secured-deny-all/inheritDenyAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }

// SecurityPermitAllEndpoint tests
    @RunAsClient
    @Test(description = "Verify that a method covered by inherited PermitAll is allowed")
    public void inheritPermitAll() throws Exception {
        Reporter.log("Begin inheritPermitAll");
        String token = TokenUtils.generateTokenString("/PermitAllToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-permit-all/inheritPermitAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with DenyAll override by is denied")
    public void overridePermitAllWithDenyAll() throws Exception {
        Reporter.log("Begin overridePermitAllWithDenyAll");
        String token = TokenUtils.generateTokenString("/PermitAllToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-permit-all/overridePermitAllWithDenyAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with valid roles allowed")
    public void overridePermitAllWithRoles() throws Exception {
        Reporter.log("Begin overridePermitAllWithRoles");
        String token = TokenUtils.generateTokenString("/PermitAllToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-permit-all/overridePermitAllWithRoles";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with roles not in PermitAllToken by is denied")
    public void overridePermitAllWithBadRoles() throws Exception {
        Reporter.log("Begin overridePermitAllWithBadRoles");
        String token = TokenUtils.generateTokenString("/PermitAllToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-permit-all/overridePermitAllWithBadRoles";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    // SecurityRolesAllowedEndpoint tests
    @RunAsClient
    @Test(description = "Verify that a method covered by inherited RolesAllowed is allowed")
    public void inheritRolesAllowed() throws Exception {
        Reporter.log("Begin inheritRolesAllowed");
        String token = TokenUtils.generateTokenString("/RolesAllowedToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-roles-allowed/inheritRolesAllowed";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with DenyAll override by is denied")
    public void overrideWithDenyAll() throws Exception {
        Reporter.log("Begin overrideWithDenyAll");
        String token = TokenUtils.generateTokenString("/RolesAllowedToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-roles-allowed/overrideWithDenyAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with valid roles override by is allowed")
    public void overrideRoles() throws Exception {
        Reporter.log("Begin overrideWithDenyAll");
        String token = TokenUtils.generateTokenString("/RolesAllowedToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-roles-allowed/overrideRoles";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with bad roles override by is denied")
    public void overrideWithBadRoles() throws Exception {
        Reporter.log("Begin overrideWithDenyAll");
        String token = TokenUtils.generateTokenString("/RolesAllowedToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-roles-allowed/overrideWithBadRoles";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_FORBIDDEN);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
    @RunAsClient
    @Test(description = "Verify that a method with PermitAll accessed with bad roles is allowed")
    public void overrideWithPermitAll() throws Exception {
        Reporter.log("Begin overrideWithPermitAll");
        String token = TokenUtils.generateTokenString("/RolesAllowedPermitAllToken.json");
        String uri = baseURL.toExternalForm() + "app/secured-roles-allowed/overrideWithPermitAll";
        System.out.printf("uri: %s\n", uri);
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri);
        Response response = echoEndpointTarget.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String reply = response.readEntity(String.class);
        Reporter.log(reply);
    }
}
