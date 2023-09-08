/*
 * 09/07/23 Matthew Donovan
 *  Updated imports to use jakarta.* instead of javax.* and updated code to support DropWizard 4.0.0
 */
package com.github.toastshaman.dropwizard.auth.jwt;

import io.dropwizard.auth.Auth;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

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