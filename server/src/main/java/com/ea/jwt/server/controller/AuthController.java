package com.ea.jwt.server.controller;

import com.ea.jwt.server.dto.JsonTokenResponse;
import com.ea.jwt.server.security.AuthClient;
import com.ea.jwt.server.service.JwtTokenService;
import com.ea.jwt.server.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;

    private static final String GRANT_TYPE = "grant-type";
    private static final String JWT_GRANT_TYPE = "jwt-bearer";
    private static final String JWT_ASSERTION = "assertion";

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public ResponseEntity token(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");

        final String grantTypeValue = request.getHeader(GRANT_TYPE);
        if (JWT_GRANT_TYPE.equals(grantTypeValue)) {
            String jwtToken = request.getHeader(JWT_ASSERTION);
            AuthClient authClient = tokenService.validateClientByJwtToken(jwtToken);
            if (authClient.isVerified()) {
                LOG.debug("Client '{}' correctly validated with JWT-Token '{}' provided", authClient.getName(), jwtToken);
//                String user = tokenService.extractUserFromToken(jwtToken);
                String accessToken = tokenService.getAccessToken(authClient.getClientId());
                JsonTokenResponse jsonToken = new JsonTokenResponse(accessToken, "jwt", JwtTokenService.accessTokenExpirationInMin, null, null);
                LOG.debug("Created accessToken {} for the Client '{}", accessToken, authClient.getName());
                return new ResponseEntity<>(jsonToken, HttpStatus.OK);
            } else {
                LOG.warn("Authorization failed! A server is asking for an accessToken, but the provided jwt token '{}' in the header '{}' is not valid!", jwtToken, JWT_ASSERTION);
                return new ResponseEntity<>("Wrong grant-type header for requesting accessToken!", HttpStatus.FORBIDDEN);
            }
        } else {
            LOG.warn("Authorization failed! Wrong Headers: '{}' is missing or contains a wrong value", GRANT_TYPE);
        }

        LOG.warn("Wrong Headers! Missing: '{}' and '{}'", GRANT_TYPE, JWT_GRANT_TYPE);
        return new ResponseEntity<>("Wrong Headers!", HttpStatus.FORBIDDEN);
    }

}
