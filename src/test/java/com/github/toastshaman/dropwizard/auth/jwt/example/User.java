package com.github.toastshaman.dropwizard.auth.jwt.example;

public class User {

    private final String username;

    public User(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
