package org.wildfly.swarm.mpjwtauth.jaxrs;


import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ejb.EJB;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import java.security.Principal;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.microprofile.jwt.JWTPrincipal;

@Path("/endp")
public class RolesEndpoint {

    @EJB
    private IService serviceEJB;

    @GET
    @Path("/echo")
    @RolesAllowed("Echoer")
    public String echoInput(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        return input + ", user="+user.getName();
    }

    @GET
    @Path("/echo2")
    @RolesAllowed("NoSuchUser")
    public String echoInput2(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        String name = user != null ? user.getName() : "<null>";
        return input + ", user="+name;
    }

    @GET
    @Path("/echo3")
    @RolesAllowed("EndpointCustom")
    public String echoInput3(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        return input + ", user="+user.getName();
    }

    @GET
    @Path("/getPrincipalClass")
    @RolesAllowed("Tester")
    public String getPrincipalClass(@Context SecurityContext sec) {
        Principal user = sec.getUserPrincipal();
        HashSet<Class> interfaces = new HashSet<>();
        Class current = user.getClass();
        while(current.equals(Object.class) == false) {
            Class[] tmp = current.getInterfaces();
            for(Class c : tmp) {
                interfaces.add(c);
            }
            current = current.getSuperclass();
        }
        StringBuilder tmp = new StringBuilder();
        for(Class iface : interfaces) {
            tmp.append(iface.getTypeName());
            tmp.append(',');
        }
        tmp.setLength(tmp.length()-1);
        return tmp.toString();
    }

    @GET
    @Path("/getEJBPrincipalClass")
    @RolesAllowed("Tester")
    public String getEJBPrincipalClass(@Context SecurityContext sec) {
        return serviceEJB.getPrincipalClass();
    }

    @GET
    @Path("/getEJBSubjectClass")
    @RolesAllowed("Tester")
    public String getEJBSubjectClass(@Context SecurityContext sec) throws Exception {
        return serviceEJB.getSubjectClass();
    }

    @GET
    @Path("/getSubjectClass")
    @RolesAllowed("Tester")
    public String getSubjectClass(@Context SecurityContext sec) throws Exception {
        Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        Set<? extends Principal> principalSet = subject.getPrincipals(JWTPrincipal.class);
        if (principalSet.size() > 0)
            return "subject.getPrincipals(JWTPrincipal.class) ok";
        throw new IllegalStateException("subject.getPrincipals(JWTPrincipal.class) == 0");
    }

    /**
     * This
     * @return
     */
    @GET
    @Path("/needsGroup1Mapping")
    @RolesAllowed("Group1MappedRole")
    public String needsGroup1Mapping(@Context SecurityContext sec) {
        Principal user = sec.getUserPrincipal();
        sec.isUserInRole("group1");
        return user.getName();
    }

    @GET
    @Path("/heartbeat")
    @PermitAll
    public String heartbeat() {
        return "Heartbeat: "+ new Date(System.currentTimeMillis()).toString();
    }
}
