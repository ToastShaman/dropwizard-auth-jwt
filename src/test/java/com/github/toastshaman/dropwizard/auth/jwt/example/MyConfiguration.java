/*
 * 09/07/23 Matthew Donovan
 *  Updated imports to use jakarta.* instead of javax.* and updated code to support DropWizard 4.0.0
 */
package com.github.toastshaman.dropwizard.auth.jwt.example;

import io.dropwizard.core.Configuration;
import org.hibernate.validator.constraints.NotEmpty;

import java.io.UnsupportedEncodingException;

public class MyConfiguration extends Configuration {

    @NotEmpty
    private String jwtTokenSecret = "dfwzsdzwh823zebdwdz772632gdsbd";

    public byte[] getJwtTokenSecret() throws UnsupportedEncodingException {
        return jwtTokenSecret.getBytes("UTF-8");
    }
}
