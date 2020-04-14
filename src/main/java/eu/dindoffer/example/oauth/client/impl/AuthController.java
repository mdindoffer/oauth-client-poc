package eu.dindoffer.example.oauth.client.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Controller
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private OAuth2RestOperations exampleProviderRestTemplate;

    public AuthController(OAuth2RestOperations exampleProviderRestTemplate) {
        this.exampleProviderRestTemplate = exampleProviderRestTemplate;
    }

    @GetMapping("/initNewAuth")
    public void initNewAuth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("Initiating new auth request");
        //clear the session
        clearCurrentAuthentication(request);
        //Create a new session and store any data if needed (omitted for brevity)
        HttpSession session = request.getSession();
        //Redirect to initiate OAuth flow with an example provider
        response.sendRedirect("/oauth2/authorization/example-provider");
    }

    @GetMapping(value = "/authorize/oauth2/code/{providerId}", params = "!error")
    public void handleSuccessfulAuth(@PathVariable String providerId) {
        LOG.info("OAuth grant successful for provider {}", providerId);
        //try to obtain access token
        OAuth2AccessToken accessToken = exampleProviderRestTemplate.getAccessToken();
        LOG.info("Obtained access token: {}", accessToken);
        //Now do stuff, e.g. try to call protected resources with an access token...
    }

    @GetMapping(value = "/authorize/oauth2/code/{providerId}", params = "error")
    public void handleFailedAuth(@PathVariable("providerId") String providerId,
                                 @RequestParam("error") String error,
                                 @RequestParam(value = "error_description", required = false) String errorDescription,
                                 @RequestParam(value = "error_uri", required = false) String errorUri) {
        LOG.error("Caught an unsuccessful auth for provider {}, with error {}", providerId, error);
    }

    /**
     * Performs a manual logout by removing any current authentication present.
     * Invalidates the session of the provided request, removes the Authentication
     * object from security context and detaches the security context from the current thread.
     *
     * @param request current HTTP request
     */
    private void clearCurrentAuthentication(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            LOG.debug("Invalidating session:{}", session.getId());
            session.invalidate();
        }
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(null);
        SecurityContextHolder.clearContext();
    }
}
