package com.ea.jwt.server.controller;

import com.ea.jwt.server.dto.JsonTokenResponse;
import com.ea.jwt.server.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.ea.jwt.server.service.TokenService.TOKEN_EXPIRE_IN_MIN;

@RestController
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public ResponseEntity token(Authentication authentication) {
        LOG.debug("Token requested for user: '{}'", authentication.getName());
        String token = tokenService.generateToken(authentication);
        JsonTokenResponse jsonToken = new JsonTokenResponse(token, "jwt",
                TOKEN_EXPIRE_IN_MIN, null, null);
        LOG.debug("Granted for user {}, accessToken {}", authentication.getName(), token);
        return new ResponseEntity<>(jsonToken, HttpStatus.OK);
    }

}
