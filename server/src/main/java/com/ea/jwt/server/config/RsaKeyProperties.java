package com.ea.jwt.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ConfigurationProperties
public class RsaKeyProperties {

    @Value("${rsa.public-key}")
    private RSAPublicKey publicKey;
    @Value("${rsa.private-key}")
    private RSAPrivateKey privateKey;

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public RSAPrivateKey privateKey() {
        return privateKey;
    }

}
