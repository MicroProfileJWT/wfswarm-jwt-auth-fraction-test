package org.wildfly.swarm.mpjwtauth.jaxrs;

import org.eclipse.microprofile.jwt.JWTPrincipal;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.Filters;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.swarm.mpjwtauth.util.TokenUtils;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashSet;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

/**
 *
 */
@RunWith(Arquillian.class)
public class RolesAllowedTest {

    private static String token;
    @ArquillianResource
    private URL baseURL;

    @Deployment(testable = false)
    public static WebArchive createDeployment() throws IOException {
        // Disable remote repository resolution
        System.setProperty("swarm.resolver.offline", "true");

        URL publicKey = RolesAllowedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "RolesAllowedTest.war")
                .addAsResource(publicKey, "/publicKey.pem")
                .addAsResource("project-defaults.yml", "/project-defaults.yml")
                //.addAsResource("project-defaults-basic.yml", "/project-defaults.yml")
                .addPackages(true, Filters.exclude(".*Test.*"), RolesEndpoint.class.getPackage())
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsWebInfResource("jwt-users.properties", "classes/jwt-users.properties")
                .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/jboss-web.xml", "jboss-web.xml")
                ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass
    public static void generateToken() throws Exception {
        token = TokenUtils.generateTokenString("/RolesEndpoint.json");
    }
    @Test
    public void callEchoNoAuth() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, response.getStatus());
    }

    @Test
    public void callEchoExpiredToken() throws Exception {
        HashSet<TokenUtils.InvalidFields> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidFields.EXP);
        String token = TokenUtils.generateTokenString("/RolesEndpoint.json", invalidFields);
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, response.getStatus());
        String reply = response.readEntity(String.class);
    }

    /**
     * Used to test how a standard auth-method works with the authorization layer.
     * @throws Exception
     */
    @Test
    @Ignore
    public void callEchoBASIC() throws Exception {
        byte[] tokenb = Base64.getEncoder().encode("jdoe@example.com:password".getBytes());
        String token = new String(tokenb);
        System.out.printf("basic: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "BASIC "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        Assert.assertEquals("hello, user=jdoe@example.com", reply);
    }

    @Test(timeout = 1000000)
    public void callEcho() throws Exception {
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        Assert.assertEquals("hello, user=jdoe@example.com", reply);
    }

    @Test(timeout = 1000000)
    public void callEcho2() throws Exception {
        System.out.printf("jwt: %s\n", token);

        String uri = baseURL.toExternalForm() + "/endp/echo2";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        String reply = response.readEntity(String.class);
        Assert.assertEquals(HttpURLConnection.HTTP_FORBIDDEN, response.getStatus());
    }

    @Test
    public void getPrincipalClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJWTPrincipal = false;
        for(String iface : ifaces) {
            hasJWTPrincipal |= iface.equals(JWTPrincipal.class.getTypeName());
        }
        Assert.assertTrue("PrincipalClass has JWTPrincipal interface", hasJWTPrincipal);
    }
    @Test
    public void getSubjectClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getSubjectClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @Test
    public void getServletPrincipalClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/ServiceServlet/getPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJWTPrincipal = false;
        for(String iface : ifaces) {
            hasJWTPrincipal |= iface.equals(JWTPrincipal.class.getTypeName());
        }
        Assert.assertTrue("PrincipalClass has JWTPrincipal interface", hasJWTPrincipal);
    }

    @Test
    public void getServletSubjectClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/ServiceServlet/getSubject";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @Test
    public void testEJBPrincipalClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getEJBPrincipalClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        String[] ifaces = reply.split(",");
        boolean hasJWTPrincipal = false;
        for(String iface : ifaces) {
            hasJWTPrincipal |= iface.equals(JWTPrincipal.class.getTypeName());
        }
        Assert.assertTrue("EJB PrincipalClass has JWTPrincipal interface", hasJWTPrincipal);
    }

    @Test
    public void getEJBSubjectClass() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/getEJBSubjectClass";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    /**
     * This test requires that the server provide a mapping from the group1 grant in the token to a Group1MappedRole
     * application declared role.
     */
    @Test
    public void testNeedsGroup1Mapping() {
        String uri = baseURL.toExternalForm() + "/endp/needsGroup1Mapping";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        String reply = response.readEntity(String.class);
        System.out.println(reply);
    }

    @Test
    public void callHeartbeat() throws Exception {
        String uri = baseURL.toExternalForm() + "/endp/heartbeat";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("input", "hello")
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).get();
        Assert.assertEquals(HttpURLConnection.HTTP_OK, response.getStatus());
        Assert.assertTrue("Heartbeat:", response.readEntity(String.class).startsWith("Heartbeat:"));
    }
}
