package org.wildfly.swarm.mpjwtauth.container.jaxrs;


import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
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

import static org.wildfly.swarm.mpjwtauth.container.jaxrs.TCKConstants.TEST_GROUP_CDI_PROVIDER;


/**
 * Tests of injection JsonWebToken claims using the {@linkplain javax.inject.Provider} interface.
 */
public class ProviderInjectionTest extends Arquillian {

    /**
     * The test generated JWT token string
     */
    private static String token;
    // Time claims in the token
    private static Long iatClaim;
    private static Long authTimeClaim;
    private static Long expClaim;

    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    public static WebArchive createDeployment() throws IOException {
        System.setProperty("swarm.resolver.offline", "true");
        System.setProperty("swarm.debug.port", "8888");
        //System.setProperty("org.jboss.weld.development", "true");

        URL publicKey = ClaimValueInjectionTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "ProviderInjectionTest.war")
                .addAsResource(publicKey, "/publicKey.pem")
                .addAsManifestResource(publicKey, "/MP-JWT-SIGNER")
                .addAsResource("project-defaults.yml", "/project-defaults.yml")
                .addClass(ProviderInjectionEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/jboss-web.xml", "jboss-web.xml")
                ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @BeforeClass(alwaysRun=true)
    public static void generateToken() throws Exception {
        HashMap<String, Long> timeClaims = new HashMap<>();
        token = TokenUtils.generateTokenString("/Token1.json", null, timeClaims);
        iatClaim = timeClaims.get(Claims.iat.name());
        authTimeClaim = timeClaims.get(Claims.auth_time.name());
        expClaim = timeClaims.get(Claims.exp.name());
    }

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected token issuer claim is as expected")
    public void verifyIssuerClaim() throws Exception {
        Reporter.log("Begin verifyIssuerClaim");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedIssuer";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iss.name(), TCKConstants.TEST_ISSUER)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected raw token claim is as expected")
    public void verifyInjectedRawToken() throws Exception {
        Reporter.log("Begin verifyInjectedRawToken\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedRawToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.raw_token.name(), token)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected jti claim is as expected")
    public void verifyInjectedJTI() throws Exception {
        Reporter.log("Begin verifyInjectedJTI\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedJTI";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.jti.name(), "a-123")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected aud claim is as expected")
    public void verifyInjectedAudience() throws Exception {
        Reporter.log("Begin verifyInjectedAudience\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedAudience";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.aud.name(), "s6BhdRkqt3")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected iat claim is as expected")
    public void verifyInjectedIssuedAt() throws Exception {
        Reporter.log("Begin verifyInjectedIssuedAt\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedIssuedAt";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iat.name(), iatClaim)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected sub claim is as expected")
    public void verifyInjectedOptionalSubject() throws Exception {
        Reporter.log("Begin verifyInjectedOptionalSubject\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedOptionalSubject";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.sub.name(), "24400320")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected raw token claim is as expected")
    public void verifyInjectedOptionalAuthTime() throws Exception {
        Reporter.log("Begin verifyInjectedOptionalAuthTime\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedOptionalAuthTime";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected custom claim is missing as expected")
    public void verifyInjectedOptionalCustomMissing() throws Exception {
        Reporter.log("Begin verifyInjectedOptionalCustomMissing\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedOptionalCustomMissing";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customString claim is as expected")
    public void verifyInjectedCustomString() throws Exception {
        Reporter.log("Begin verifyInjectedCustomString\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomString";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", "customStringValue")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customInteger claim is as expected")
    public void verifyInjectedCustomInteger() throws Exception {
        Reporter.log("Begin verifyInjectedCustomInteger\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomInteger";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", 123456789)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customDouble claim is as expected")
    public void verifyInjectedCustomDouble() throws Exception {
        Reporter.log("Begin verifyInjectedCustomDouble\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomDouble";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", 3.141592653589793)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }

    // Duplicate tests that use Token2.json to verify that @RequestScope or @Dependent scoping is in use

    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected token issuer claim is as expected")
    public void verifyIssuerClaim2() throws Exception {
        Reporter.log("Begin verifyIssuerClaim");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedIssuer";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iss.name(), TCKConstants.TEST_ISSUER)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected raw token claim is as expected")
    public void verifyInjectedRawToken2() throws Exception {
        Reporter.log("Begin verifyInjectedRawToken\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedRawToken";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.raw_token.name(), token)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected jti claim is as expected")
    public void verifyInjectedJTI2() throws Exception {
        Reporter.log("Begin verifyInjectedJTI\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedJTI";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.jti.name(), "a-123")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected aud claim is as expected")
    public void verifyInjectedAudience2() throws Exception {
        Reporter.log("Begin verifyInjectedAudience\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedAudience";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.aud.name(), "s6BhdRkqt3")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected iat claim is as expected")
    public void verifyInjectedIssuedAt2() throws Exception {
        Reporter.log("Begin verifyInjectedIssuedAt\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedIssuedAt";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.iat.name(), iatClaim)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected sub claim is as expected")
    public void verifyInjectedOptionalSubject2() throws Exception {
        Reporter.log("Begin verifyInjectedOptionalSubject\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedOptionalSubject";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.sub.name(), "24400320")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected raw token claim is as expected")
    public void verifyInjectedOptionalAuthTime2() throws Exception {
        Reporter.log("Begin verifyInjectedOptionalAuthTime\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedOptionalAuthTime";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customString claim is as expected")
    public void verifyInjectedCustomString2() throws Exception {
        Reporter.log("Begin verifyInjectedCustomString\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomString";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", "customStringValue")
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customInteger claim is as expected")
    public void verifyInjectedCustomInteger2() throws Exception {
        Reporter.log("Begin verifyInjectedCustomInteger\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomInteger";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", 123456789)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
    @RunAsClient
    @Test(groups = TEST_GROUP_CDI_PROVIDER,
            description = "Verify that the injected customDouble claim is as expected")
    public void verifyInjectedCustomDouble2() throws Exception {
        Reporter.log("Begin verifyInjectedCustomDouble\n");
        String uri = baseURL.toExternalForm() + "/endp/verifyInjectedCustomDouble";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                .queryParam("value", 3.141592653589793)
                .queryParam(Claims.auth_time.name(), authTimeClaim);
        Response response = echoEndpointTarget.request(MediaType.APPLICATION_JSON).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_OK);
        String replyString = response.readEntity(String.class);
        JsonReader jsonReader = Json.createReader(new StringReader(replyString));
        JsonObject reply = jsonReader.readObject();
        Reporter.log(reply.toString());
        Assert.assertTrue(reply.getBoolean("pass"), reply.getString("msg"));
    }
}
