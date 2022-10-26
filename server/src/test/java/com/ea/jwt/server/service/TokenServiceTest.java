package com.ea.jwt.server.service;

import com.auth0.jwt.algorithms.Algorithm;
import com.ea.jwt.server.security.AuthClient;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TokenServiceTest extends ServiceTest {

    @Mock
    private JwtEncoder jwtEncoder;

    @InjectMocks
    private TokenService tokenService = new JwtTokenService(jwtEncoder);

    @Test
    public void test_validateJwtTokenUsingEncoder() {
        // Given
        final String serverId = "serverId";
        final String serverSecret = "serverSecret";

        final String clientName = "fakeClientName";
        final String clientId = "fakeClientName";
        final String clientSecret = "clientSecret";
        final String clientSubject = "acc:jane@DEMO";
        final String clientUser = "jane";

        List<AuthClient> registeredClients = Arrays.asList(
                new AuthClient("name1", "id1", "secret1"),
                new AuthClient(clientName, clientId, clientSecret)); // will generate JWT for this client
        ReflectionTestUtils.setField(tokenService, "serverId", serverId);
        ReflectionTestUtils.setField(tokenService, "serverSecret", serverSecret);
        ReflectionTestUtils.setField(tokenService, "registeredClients", registeredClients);
        ReflectionTestUtils.setField(tokenService, "accessTokenExpirationInMin", 1);

        // When
        // 1. Create JWT token for client "fakeClientName"
        String jwtToken = tokenService.getAccessToken(clientId);
        assertNotNull(jwtToken);
        // 2. Validate the JWT token with the list of clients secrets and fetch the right Client
        AuthClient authClient = tokenService.validateClientByJwtToken(jwtToken);
        assertNotNull(authClient);
        assertTrue(authClient.isVerified());
    }

    @Test
    public void test_validateJwtToken() {
        // Given
        final String serverId = "serverId";
        final String serverSecret = "serverSecret";

        final String clientName = "fakeClientName";
        final String clientId = "fakeClientName";
        final String clientSecret = "clientSecret";
        final String clientSubject = "acc:jane@DEMO";
        final String clientUser = "jane";

        List<AuthClient> registeredClients = Arrays.asList(
                new AuthClient("name1", "id1", "secret1"),
                new AuthClient(clientName, clientId, clientSecret)); // will generate JWT for this client
        ReflectionTestUtils.setField(tokenService, "serverId", serverId);
        ReflectionTestUtils.setField(tokenService, "serverSecret", serverSecret);
        ReflectionTestUtils.setField(tokenService, "registeredClients", registeredClients);
        ReflectionTestUtils.setField(tokenService, "accessTokenExpirationInMin", 1);

        // When
        // 1. Create JWT token for client "fakeClientName"
        String jwtToken = generateJwtToken(clientId, clientSecret, clientSubject, clientUser);
        assertNotNull(jwtToken);
        // 2. Validate the JWT token with the list of clients secrets and fetch the right Client
        AuthClient authClient = tokenService.validateClientByJwtToken(jwtToken);
        assertNotNull(authClient);
        assertTrue(authClient.isVerified());
    }

    private String generateJwtToken(String issuer, String secret, String subject, String user) {
        try {
            Instant now = Instant.now();
            Algorithm algorithm = Algorithm.HMAC256(secret);

            String token = com.auth0.jwt.JWT.create()
                    .withIssuer(issuer)
                    .withSubject(subject)
                    .withIssuedAt(Date.from(now))
                    .withClaim("user", user)
                    .sign(algorithm);
            return token;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void test_printToken()  {
        final String clientId = "GoHiringClientId";
        final String clientSecret = "GoHiringClientSecret";
        final String clientSubject = "acc:jane@demo";
        final String clientUser = "jane";

        String token = generateJwtToken(clientId, clientSecret, clientSubject, clientUser);
        System.out.println(token);
    }
}
