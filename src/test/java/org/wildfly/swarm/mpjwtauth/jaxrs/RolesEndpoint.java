package org.wildfly.swarm.mpjwtauth.jaxrs;


import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ejb.EJB;
import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import java.security.Principal;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/endp")
public class RolesEndpoint {

    @EJB
    private IService serviceEJB;
    @Inject
    private JsonWebToken jwtPrincipal;
    @Inject
    @Claim("raw_token")
    private ClaimValue<String> rawToken;
    @Inject
    @Claim("iss")
    private ClaimValue<String> issuer;
    @Inject
    @Claim("jti")
    private ClaimValue<String> jti;
    @Inject
    @Claim("aud")
    private ClaimValue<Set<String>> aud;
    @Inject
    @Claim("roles")
    private ClaimValue<String[]> roles;
    @Inject
    @Claim("iat")
    private ClaimValue<Long> issuedAt;
    @Inject
    @Claim("sub")
    private ClaimValue<Optional<String>> optSubject;
    @Inject
    @Claim("auth_time")
    private ClaimValue<Optional<Long>> authTime;


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
    @Path("/getInjectedPrincipal")
    public String getInjectedPrincipal(@Context SecurityContext sec) {
        HashSet<Class> interfaces = new HashSet<>();
        Class current = jwtPrincipal.getClass();
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

    /**
     * Verify that values exist and that types match the corresponding Claims enum
     * @return a series of pass/fail statements regarding the check for each injected claim
     */
    @GET
    @Path("/getInjectedClaims")
    public String getInjectedIssuer(@QueryParam("iss") String iss,
                                    @QueryParam("raw_token") String raw_token,
                                    @QueryParam("jti") String jwtID,
                                    @QueryParam("aud") String audience,
                                    @QueryParam("iat") Long iat,
                                    @QueryParam("sub") String subject,
                                    @QueryParam("auth_time") Long authTime) {
        StringBuilder tmp = new StringBuilder("getInjectedClaims\n");
        // iss
        String issValue = issuer.getValue();
        if(issValue == null || issValue.length() == 0) {
            tmp.append(Claims.iss.name()+"value is null or empty\n");
        }
        else if(issValue.equals(iss)) {
            tmp.append(Claims.iss.name()+" PASS\n");
        } else {
            tmp.append(Claims.iss.name()+" FAIL\n");
        }
        // raw_token
        String rawTokenValue = rawToken.getValue();
        if(rawTokenValue == null || rawTokenValue.length() == 0) {
            tmp.append(Claims.raw_token.name()+" value is null or empty\n");
        }
        else if(rawTokenValue.equals(raw_token)) {
            tmp.append(Claims.raw_token.name()+" PASS\n");
        } else {
            tmp.append(Claims.raw_token.name()+" FAIL\n");
        }
        // jti
        String jtiValue = jti.getValue();
        if(jtiValue == null || jtiValue.length() == 0) {
            tmp.append(Claims.jti.name()+" value is null or empty\n");
        }
        else if(jtiValue.equals(jwtID)) {
            tmp.append(Claims.jti.name()+" PASS\n");
        } else {
            tmp.append(Claims.jti.name()+" FAIL\n");
        }
        // aud
        Set<String> audValue = aud.getValue();
        if(audValue == null || audValue.size() == 0) {
            tmp.append(Claims.aud.name()+" value is null or empty\n");
        }
        else if(audValue.contains(audience)) {
            tmp.append(Claims.aud.name()+" PASS\n");
        } else {
            tmp.append(Claims.aud.name()+" FAIL\n");
        }
        // iat
        Long iatValue = issuedAt.getValue();
        if(iatValue == null || iatValue.intValue() == 0) {
            tmp.append(Claims.iat.name()+" value is null or zero\n");
        }
        else if(iatValue.equals(iat)) {
            tmp.append(Claims.iat.name()+" PASS\n");
        } else {
            tmp.append(Claims.iat.name()+" FAIL\n");
        }
        // sub
        Optional<String> optSubValue = optSubject.getValue();
        if(optSubValue == null || !optSubValue.isPresent()) {
            tmp.append(Claims.sub.name()+" value is null or missing\n");
        }
        else if(optSubValue.get().equals(subject)) {
            tmp.append(Claims.sub.name()+" PASS\n");
        } else {
            tmp.append(Claims.sub.name()+" FAIL\n");
        }
        // auth_time
        Optional<Long> optAuthTimeValue = this.authTime.getValue();
        if(optAuthTimeValue == null || !optAuthTimeValue.isPresent()) {
            tmp.append(Claims.auth_time.name()+" value is null or missing\n");
        }
        else if(optAuthTimeValue.get().equals(authTime)) {
            tmp.append(Claims.auth_time.name()+" PASS\n");
        } else {
            tmp.append(Claims.auth_time.name()+" FAIL\n");
        }

        return tmp.toString();
    }

    @GET
    @Path("/getInjectedPrincipalNoAuth")
    public String getInjectedPrincipalNoAuth(@Context SecurityContext sec) {
        System.err.printf("getInjectedPrincipalNoAuth, sec.UP:%s, IP:%s\n", sec.getUserPrincipal(), jwtPrincipal);
        return this.jwtPrincipal == null ? "NO_INJECTED_PRINCIPAL" : "INJECTED_PRINCIPAL";
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
        Set<? extends Principal> principalSet = subject.getPrincipals(JsonWebToken.class);
        if (principalSet.size() > 0)
            return "subject.getPrincipals(JsonWebToken.class) ok";
        throw new IllegalStateException("subject.getPrincipals(JsonWebToken.class) == 0");
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
