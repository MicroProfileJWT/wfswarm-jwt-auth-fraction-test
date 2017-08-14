package org.wildfly.swarm.mpjwtauth.jaxrs;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.ServletException;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.microprofile.jwt.JsonWebToken;

@HttpConstraint(rolesAllowed={"Tester"})
@WebServlet("/ServiceServlet/*")
public class ServiceServlet extends HttpServlet {
    @EJB
    private IService serviceEJB;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Principal user = req.getUserPrincipal();
        String pathInfo = req.getPathInfo();
        System.out.printf("pathInfo=%s\n", pathInfo);

        String result = "";
        if(pathInfo.endsWith("/getSubject")) {
            System.out.printf("Calling getSubject\n");
            result = getSubject(resp);
        } else {
            System.out.printf("Calling getPrincipalClass\n");
            result = getPrincipalClass(user);
        }
        resp.getWriter().write(result);
    }
    private String getPrincipalClass(Principal user) {
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
    private String getSubject(HttpServletResponse response) throws IOException {
        try {
            Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");
            Set<? extends Principal> principalSet = subject.getPrincipals(JsonWebToken.class);
            if(principalSet.size() > 0)
                return "subject.getPrincipals(JsonWebToken.class) ok";
            response.sendError(500, "subject.getPrincipals(JsonWebToken.class) == 0");
        } catch (PolicyContextException e) {
            e.printStackTrace();
            response.sendError(500, e.getMessage());
        }
        return "";
    }
    private String callEJB(HttpServletResponse response) throws IOException {
        return "";
    }
}
