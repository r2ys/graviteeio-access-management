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
package io.gravitee.am.gateway.handler.vertx.handler.oidc.handler;

import io.gravitee.am.common.jwt.JWT;
import io.gravitee.am.gateway.handler.jwt.JwtService;
import io.gravitee.am.gateway.handler.oauth2.client.ClientSyncService;
import io.gravitee.am.gateway.handler.oauth2.token.Token;
import io.gravitee.am.gateway.handler.oauth2.token.impl.AccessToken;
import io.gravitee.am.gateway.handler.oauth2.utils.OIDCParameters;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.MediaType;
import io.reactivex.Single;
import io.vertx.core.Handler;
import io.vertx.core.json.Json;
import io.vertx.reactivex.ext.web.RoutingContext;

import java.util.Date;
import java.util.Map;

/**
 * @author Alexandre FARIA (contact at alexandrefaria.net)
 * @author GraviteeSource Team
 */
public class UserinfoResponseHandler implements Handler<RoutingContext> {

    private ClientSyncService clientSyncService;
    private JwtService jwtService;

    public UserinfoResponseHandler(ClientSyncService clientSyncService, JwtService jwtService) {
        this.clientSyncService = clientSyncService;
        this.jwtService = jwtService;
    }

    @Override
    public void handle(RoutingContext context) {
        AccessToken accessToken = context.get(Token.ACCESS_TOKEN);
        Map<String, Object> claims = context.get(OIDCParameters.CLAIMS);

        clientSyncService.findByClientId(accessToken.getClientId())
                .flatMapSingle(client -> {
                    if(client.getUserinfoSignedResponseAlg()==null) {
                        context.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
                        return Single.just(Json.encodePrettily(claims));
                    }
                    else {
                        context.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JWT);

                        JWT jwt = new JWT(claims);
                        jwt.setIss((String)accessToken.getAdditionalInformation().get("iss"));
                        jwt.setSub(accessToken.getSubject());
                        jwt.setAud(accessToken.getClientId());
                        jwt.setIat(new Date().getTime() / 1000l);
                        jwt.setExp(accessToken.getExpireAt().getTime() / 1000l);

                        return jwtService.encodeUserinfo(jwt,client);
                    }
                })
                .subscribe(
                        buffer -> context.response()
                                .putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
                                .putHeader(HttpHeaders.PRAGMA, "no-cache")
                                .end(buffer)
                        ,
                        error -> context.fail(error)
                );
    }
}
