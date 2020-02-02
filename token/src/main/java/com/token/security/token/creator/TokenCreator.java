package com.token.security.token.creator;

import com.core.model.ApplicationUser;
import com.core.property.JwtConfiguration;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {
    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public SignedJWT createSignedJwt(Authentication auth) {
        log.info("Starting to create the signed JWT");
        ApplicationUser user = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, user);
        KeyPair keyPair = generateKeyPar();

        log.info("Building JWK from keys");

        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(jwk)
                        .type(JOSEObjectType.JWT)
                        .build(),
                jwtClaimSet);
        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);

        log.info("Serialized token '{}'", signedJWT.serialize());
        return signedJWT;
    }

    public String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Start the encrypting method");

        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));

        jweObject.encrypt(directEncrypter);

        return jweObject.serialize();
    }

    private JWTClaimsSet createJWTClaimSet (Authentication auth, ApplicationUser applicationUser){
        log.info("Creating the JWTClaimSet object for '{}'", applicationUser);
        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities",
                        auth.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(toList()))
                .claim("userId", applicationUser.getId())
                .issuer("http://course.com")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPar(){
        log.info("Generating keys");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.generateKeyPair();
    }
}
