package org.wildfly.swarm.mpjwtauth.jaxrs;

import javax.ejb.Remote;

@Remote
public interface IService {
    public String echo(String input);
    public String getPrincipalClass();
    public String getSubjectClass() throws Exception;
}
