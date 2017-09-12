package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import java.io.IOException;
import java.net.URL;

import org.jboss.arquillian.container.spi.client.container.DeploymentException;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.ShouldThrowException;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.annotations.Test;

import static org.wildfly.swarm.mpjwtauth.container.jaxrs.TCKConstants.TEST_GROUP_CDI;

/**
 *
 */
public class AppScopedTest extends Arquillian {
    /**
     * We expect this to fail with a deployment exception
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    @ShouldThrowException(DeploymentException.class)
    public static WebArchive createDeployment() throws IOException {
        URL publicKey = AppScopedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "AppScopedTest.war")
                .addAsResource(publicKey, "/publicKey.pem")
                .addClass(AppScopedEndpoint.class)
                .addClass(TCKApplication.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @Test(groups = TEST_GROUP_CDI)
    @RunAsClient
    public void verifyDeploymentException() {
        Assert.fail("Should not execute as a deployment exception should have aborted all tests");
    }
}