package org.wildfly.swarm.mpjwtauth.jaxrs;


import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.Resource;
import javax.annotation.security.RolesAllowed;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;

import org.eclipse.microprofile.jwt.JWTPrincipal;

@Stateless
public class ServiceEJB implements IService {

    @Resource
    private SessionContext ctx;

    @RolesAllowed("Echoer")
    public String echo(String input) {
        Principal user = ctx.getCallerPrincipal();
        return String.format("ServiceEJB, input=%s, user=%s", input, user.getName());
    }

    @RolesAllowed("Tester")
    public String getPrincipalClass() {
        Principal user = ctx.getCallerPrincipal();
        System.out.printf("ServiceEJB.getPrincipalClass, user=%s, class=%s\n", user.getName(), user.getClass());
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
    @RolesAllowed("Tester")
    public String getSubjectClass() throws Exception {
        Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
        System.out.printf("ServiceEJB.getSubjectClass, subject=%s\n", subject);
        Set<? extends Principal> principalSet = subject.getPrincipals(JWTPrincipal.class);
        if (principalSet.size() > 0)
            return "subject.getPrincipals(JWTPrincipal.class) ok";
        assert principalSet.size() > 0;
        throw new IllegalStateException("subject.getPrincipals(JWTPrincipal.class) == 0");

    }
}
