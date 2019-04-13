/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.gateway.handler.jwt.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.am.common.jwt.JWT;
import io.gravitee.am.gateway.handler.certificate.CertificateManager;
import io.gravitee.am.gateway.handler.certificate.CertificateProvider;
import io.gravitee.am.gateway.handler.jwt.JwtService;
import io.gravitee.am.gateway.handler.oauth2.exception.InvalidTokenException;
import io.gravitee.am.gateway.handler.oidc.utils.JWKSetUtils;
import io.gravitee.am.model.Client;
import io.gravitee.am.model.jose.JWK;
import io.reactivex.Flowable;
import io.reactivex.Single;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JwtServiceImpl implements JwtService {

    private static final Logger logger = LoggerFactory.getLogger(JwtServiceImpl.class);

    @Autowired
    private CertificateManager certificateManager;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public Single<String> encode(JWT jwt, CertificateProvider certificateProvider) {
        Objects.requireNonNull(certificateProvider, "Certificate provider is required to sign JWT");
        return sign(certificateProvider, jwt);
    }

    @Override
    public Single<String> encode(JWT jwt, Client client) {
        return certificateManager.get(client.getCertificate())
                .defaultIfEmpty(certificateManager.defaultCertificateProvider())
                .flatMapSingle(certificateProvider -> encode(jwt, certificateProvider));
    }

    @Override
    public Single<String> encodeUserinfo(JWT jwt, Client client) {
        CertificateProvider certificate = certificateManager
                .providers()
                .stream()
                .filter(certificateProvider ->
                        client.getUserinfoSignedResponseAlg()!=null &&
                        client.getUserinfoSignedResponseAlg().equals(certificateProvider.getProvider().signatureAlgorithm())
                )
                .findFirst()
                .orElse(certificateManager.defaultCertificateProvider());

        return encode(jwt, certificate);
    }

    @Override
    public Single<JWT> decodeAndVerify(String jwt, Client client) {
        // use findByDomainAndId method because introspect token can be use across domains
        return certificateManager.findByDomainAndId(client.getDomain(), client.getCertificate())
                .defaultIfEmpty(certificateManager.defaultCertificateProvider())
                .flatMapSingle(certificateProvider -> decode(certificateProvider, jwt))
                .map(claims -> new JWT(claims));
    }

    @Override
    public Single<JWT> decode(String jwt) {
        return Single.create(emitter -> {
            try {
                String json = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]), "UTF-8");
                emitter.onSuccess(objectMapper.readValue(json, JWT.class));
            } catch (Exception ex) {
                logger.debug("Failed to decode JWT", ex);
                emitter.onError(new InvalidTokenException("The access token is invalid", ex));
            }
        });

    }

    private Single<String> sign(CertificateProvider certificateProvider, JWT jwt) {
        return Single.just(certificateProvider.getJwtBuilder().sign(jwt));
    }

    private Single<Map<String, Object>> decode(CertificateProvider certificateProvider, String payload) {
        return Single.just(certificateProvider.getJwtParser().parse(payload));
    }

}
