package org.wildfly.swarm.mpjwtauth.resolver;

import java.io.File;

import org.jboss.shrinkwrap.resolver.api.maven.ConfigurableMavenResolverSystem;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jboss.shrinkwrap.resolver.api.maven.repository.MavenChecksumPolicy;
import org.jboss.shrinkwrap.resolver.api.maven.repository.MavenRemoteRepositories;
import org.jboss.shrinkwrap.resolver.api.maven.repository.MavenRemoteRepository;
import org.jboss.shrinkwrap.resolver.api.maven.repository.MavenUpdatePolicy;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Simple test to validate some expectations of the maven resolver as used by wfswarm.
 */
public class ResolverTest {
    @Ignore("non-MP-JWT testing ")
    @Test
    public void testLocalSnapshot() throws Exception {

        String home = System.getenv("HOME");
        MavenRemoteRepository localM2 =
                MavenRemoteRepositories.createRemoteRepository("local-m2-repo",
                        "file://"+home+"/.m2/repository",
                        "default");
        localM2.setChecksumPolicy(MavenChecksumPolicy.CHECKSUM_POLICY_IGNORE);
        localM2.setUpdatePolicy(MavenUpdatePolicy.UPDATE_POLICY_NEVER);

        MavenRemoteRepository jbossPublic =
                MavenRemoteRepositories.createRemoteRepository("jboss-public-repository-group",
                        "https://repository.jboss.org/nexus/content/groups/public/",
                        "default");
        jbossPublic.setChecksumPolicy(MavenChecksumPolicy.CHECKSUM_POLICY_IGNORE);
        jbossPublic.setUpdatePolicy(MavenUpdatePolicy.UPDATE_POLICY_NEVER);


        MavenRemoteRepository gradleTools =
                MavenRemoteRepositories.createRemoteRepository("gradle",
                        "http://repo.gradle.org/gradle/libs-releases-local",
                        "default");
        Boolean offline = Boolean.valueOf(System.getProperty("swarm.resolver.offline", "true"));
        final ConfigurableMavenResolverSystem resolver = Maven.configureResolver()
                .withClassPathResolution(true)
                .withMavenCentralRepo(true)
                //.withRemoteRepo(localM2)
                .withRemoteRepo(jbossPublic)
                .withRemoteRepo(gradleTools)
                .workOffline(offline);

        File jar = resolver.resolve("org.eclipse.microprofile.jwt:jwt-auth-wfswarm:jar:1.0.0-SNAPSHOT")
                .withoutTransitivity()
                .asSingleFile();
        System.out.println(jar);
    }
}
