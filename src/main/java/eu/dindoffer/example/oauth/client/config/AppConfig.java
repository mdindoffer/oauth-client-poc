package eu.dindoffer.example.oauth.client.config;

import eu.dindoffer.example.oauth.client.impl.MyAccessTokenProviderChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableOAuth2Client
public class AppConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2ClientContext oauth2ClientContext;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll();
    }

    @Bean
    public OAuth2RestOperations exampleProviderRestTemplate(OAuth2ClientContext oauth2ClientContext) {
        OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(exampleRegistrationResourceDetails(), oauth2ClientContext);
//TODO Uncomment this for an attempted workaround by avoiding anonymous auth checks
//        MyAccessTokenProviderChain myAccessTokenProviderChain = new MyAccessTokenProviderChain(Collections.<AccessTokenProvider>singletonList(
//                new AuthorizationCodeAccessTokenProvider()
//        ));
//        oAuth2RestTemplate.setAccessTokenProvider(myAccessTokenProviderChain);
        return oAuth2RestTemplate;
    }

    @Bean
    @ConfigurationProperties("eu.dindoffer.example.oauth.client.oauth.example-registration")
    public AuthorizationCodeResourceDetails exampleRegistrationResourceDetails() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    @Bean
    public FilterRegistrationBean oauthLoginFilterRegistration() {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(oauth2LoginFilter());
        registration.setOrder(-100);
        return registration;
    }

    private Filter oauth2LoginFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();

        // add a new filter dedicated to an example OAuth2 provider
        OAuth2ClientAuthenticationProcessingFilter exampleOauthProviderFilter =
                new OAuth2ClientAuthenticationProcessingFilter("/oauth2/authorization/example-provider");
        OAuth2RestOperations exampleProviderRestTemplate = exampleProviderRestTemplate(oauth2ClientContext);
        exampleOauthProviderFilter.setRestTemplate(exampleProviderRestTemplate);

        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(new InMemoryTokenStore());
        exampleOauthProviderFilter.setTokenServices(defaultTokenServices);

        filters.add(exampleOauthProviderFilter);

        // add filters for additional providers here...

        filter.setFilters(filters);
        return filter;
    }
}
