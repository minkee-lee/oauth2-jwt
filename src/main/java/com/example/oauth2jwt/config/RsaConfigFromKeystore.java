package com.example.oauth2jwt.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

// RsaConfig  또는  RsaConfigFromKeystore 둘 중 하나 사용
@Slf4j
//@Configuration
public class RsaConfigFromKeystore {

    @Value("${auth.token.keystore.password}")
    private String password;

    @Value("${auth.token.keystore.private-key}")
    private String privateKey;

    @Value("${auth.token.keystore.alias}")
    private String alias;


    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsa() {
        KeyPair keyPair = loadKeypair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("kid-01")
//                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private KeyPair loadKeypair() {
        try {
            InputStream is = new ClassPathResource(privateKey).getInputStream();
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(is, password.toCharArray());
            Key privateKey = keyStore.getKey(alias, password.toCharArray());
            Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) privateKey);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}

