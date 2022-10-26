package com.ea.jwt.server.dto;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class JsonTokenResponse {

    private String accessToken;
    private String tokenType;
    private int tokeExpireInMinutes;
    private String scope;
    private String state;

    public JsonTokenResponse(){

    }

    public JsonTokenResponse(String accessToken, String tokenType, int tokeExpireInMinutes, String scope, String state) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.tokeExpireInMinutes = tokeExpireInMinutes;
        this.scope = scope;
        this.state = state;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public int getTokeExpireInMinutes() {
        return tokeExpireInMinutes;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }

    public Instant getExpireTime() {
        Instant now = Instant.now();
        now = now.plus(tokeExpireInMinutes, ChronoUnit.MINUTES);
        return now;
    }

}