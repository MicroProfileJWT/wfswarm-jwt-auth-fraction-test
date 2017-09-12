package org.wildfly.swarm.mpjwtauth.container.jaxrs;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

public class SecuredWidget {
    private String id;

    public SecuredWidget(String id) {
        this.id = id;
    }

    @GET
    public String getWidgetInfo() {
        return "SecuredWidget-"+id;
    }

    @GET
    @Path("/random")
    public String getRandom() {
        return id + "-" + Math.random() + 1000000;
    }
}
