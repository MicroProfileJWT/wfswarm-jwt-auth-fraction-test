package org.wildfly.swarm.mpjwtauth.jaxrs;

import java.io.IOException;
import java.io.InputStream;

import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.impl.base.asset.ServiceProviderAsset;
import org.junit.Test;

/**
 * Created by starksm on 7/30/17.
 */
public class WebArchiveTest {
    /**
     * Validate that adding multiple service providers results in the assest containing all providers
     */
    @Test
    public void testDupServiceProviders() throws IOException {
        WebArchive webArchive = ShrinkWrap
            .create(WebArchive.class, "RolesAllowedTest.war")
                .addAsServiceProvider("io.undertow.servlet.ServletExtension", DummyExtension.class.getName())
                .addAsServiceProvider("io.undertow.servlet.ServletExtension", Dummy2Extension.class.getName());
        Node extNode = webArchive.get("WEB-INF/classes/META-INF/services/io.undertow.servlet.ServletExtension");
        ServiceProviderAsset asset = (ServiceProviderAsset) extNode.getAsset();
        System.out.println(asset);
        InputStream is = asset.openStream();
        byte[] tmp = new byte[1024];
        int length = is.read(tmp);
        System.out.println(new String(tmp, 0, length));
    }
}
