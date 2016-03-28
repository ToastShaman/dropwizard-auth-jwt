package com.github.toastshaman.dropwizard.auth.jwt;

import io.dropwizard.auth.Auth;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.security.Principal;

@Path("/test/")
@Produces(MediaType.TEXT_PLAIN)
public class AuthResource {

    @GET
    @RolesAllowed({"ADMIN"})
    @Path("admin")
    public String show(@Auth Principal principal) {
        return "'" + principal.getName() + "' has admin privileges";
    }

    @GET
    @PermitAll
    @Path("profile")
    public String showForEveryUser(@Auth Principal principal) {
        return "'" + principal.getName() + "' has user privileges";
    }

    @GET
    @Path("implicit-permitall")
    public String implicitPermitAllAuthorization(@Auth Principal principal) {
        return "'" + principal.getName() + "' has user privileges";
    }

    @GET
    @Path("noauth")
    public String hello() {
        return "hello";
    }

    @GET
    @DenyAll
    @Path("denied")
    public String denied() {
        return "denied";
    }
}