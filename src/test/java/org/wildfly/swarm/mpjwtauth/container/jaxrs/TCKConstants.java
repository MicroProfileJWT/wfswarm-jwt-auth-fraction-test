package org.wildfly.swarm.mpjwtauth.container.jaxrs;

public class TCKConstants {
    // TestNG groups
    public static final String TEST_GROUP_UTILS="utils";
    public static final String TEST_GROUP_JWT="jwt";
    public static final String TEST_GROUP_JAXRS="jaxrs";
    public static final String TEST_GROUP_CDI="cdi";
    public static final String TEST_GROUP_CDI_JSON="cdi-json";
    public static final String TEST_GROUP_CDI_PROVIDER="cdi-provider";
    public static final String TEST_GROUP_EJB="ejb-optional";
    public static final String TEST_GROUP_SERVLET="servlet-optional";
    public static final String TEST_GROUP_JACC="jacc-optional";
    public static final String TEST_GROUP_DEBUG="debug";
    public static final String TEST_ISSUER = "https://server.example.com";
    private TCKConstants() {}
}
