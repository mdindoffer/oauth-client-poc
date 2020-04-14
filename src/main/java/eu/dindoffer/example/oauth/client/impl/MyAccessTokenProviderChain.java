package eu.dindoffer.example.oauth.client.impl;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

import java.util.List;

public class MyAccessTokenProviderChain extends AccessTokenProviderChain {

    public MyAccessTokenProviderChain(List<? extends AccessTokenProvider> chain) {
        super(chain);
    }

    /**
     * Basically the same implementation as parent, sans the:
     * 1. Anonymous auth check
     * 2. Interaction with the ClientTokenServices
     */
    @Override
    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource, AccessTokenRequest request) throws UserRedirectRequiredException, AccessDeniedException {
        OAuth2AccessToken accessToken = null;
        OAuth2AccessToken existingToken = null;
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (resource.isClientOnly() || (auth != null && auth.isAuthenticated())) {
            existingToken = request.getExistingToken();
            if (existingToken != null) {
                if (existingToken.isExpired()) {
                    OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
                    if (refreshToken != null) {
                        accessToken = refreshAccessToken(resource, refreshToken, request);
                    }
                } else {
                    accessToken = existingToken;
                }
            }
        }
        // Give unauthenticated users a chance to get a token and be redirected

        if (accessToken == null) {
            // looks like we need to try to obtain a new token.
            accessToken = obtainNewAccessTokenInternal(resource, request);

            if (accessToken == null) {
                throw new IllegalStateException(
                        "An OAuth 2 access token must be obtained or an exception thrown.");
            }
        }
        return accessToken;
    }
}
