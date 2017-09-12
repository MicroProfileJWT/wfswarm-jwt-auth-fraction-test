package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import javax.annotation.security.DenyAll;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.eclipse.microprofile.auth.LoginConfig;

@LoginConfig(authMethod = "MP-JWT", realmName = "TCK-MP-JWT")
@ApplicationPath("/app")
public class SecuredApp extends Application {
}
