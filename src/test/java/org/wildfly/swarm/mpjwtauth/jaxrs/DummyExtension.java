package org.wildfly.swarm.mpjwtauth.jaxrs;

import javax.servlet.ServletContext;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;

/**
 * Created by starksm on 7/30/17.
 */
public class DummyExtension implements ServletExtension {
    @Override
    public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {

    }
}
