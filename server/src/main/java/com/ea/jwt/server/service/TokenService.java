package com.ea.jwt.server.service;

import com.ea.jwt.server.security.AuthClient;

public interface TokenService {

    AuthClient validateClientByJwtToken(String token);

    boolean validateAccessToken(String token);

    String extractUserFromToken(String token);

    String getAccessToken(String user);
}
