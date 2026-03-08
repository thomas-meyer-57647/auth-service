package de.innologic.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SocialAuthProperties {

    private final Google google;
    private final Facebook facebook;

    public SocialAuthProperties(
            @Value("${auth.google.login.enabled:false}") boolean googleLoginEnabled,
            @Value("${auth.google.client-id:}") String googleClientId,
            @Value("${auth.google.client-secret:}") String googleClientSecret,
            @Value("${auth.google.tokeninfo-url:https://oauth2.googleapis.com/tokeninfo}") String googleTokenInfoUrl,
            @Value("${auth.google.userinfo-url:https://www.googleapis.com/oauth2/v3/userinfo}") String googleUserInfoUrl,
            @Value("${auth.facebook.login.enabled:false}") boolean facebookLoginEnabled,
            @Value("${auth.facebook.app-id:}") String facebookAppId,
            @Value("${auth.facebook.app-secret:}") String facebookAppSecret,
            @Value("${auth.facebook.userinfo-url:https://graph.facebook.com/me}") String facebookUserInfoUrl,
            @Value("${auth.facebook.api-version:v17.0}") String facebookApiVersion
    ) {
        this.google = new Google(googleLoginEnabled, googleClientId, googleClientSecret, googleTokenInfoUrl, googleUserInfoUrl);
        this.facebook = new Facebook(facebookLoginEnabled, facebookAppId, facebookAppSecret, facebookUserInfoUrl, facebookApiVersion);
    }

    public Google google() {
        return google;
    }

    public Facebook facebook() {
        return facebook;
    }

    public static class Google {
        private final boolean loginEnabled;
        private final String clientId;
        private final String clientSecret;
        private final String tokenInfoUrl;
        private final String userInfoUrl;

        private Google(boolean loginEnabled, String clientId, String clientSecret, String tokenInfoUrl, String userInfoUrl) {
            this.loginEnabled = loginEnabled;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tokenInfoUrl = tokenInfoUrl;
            this.userInfoUrl = userInfoUrl;
        }

        public boolean isLoginEnabled() {
            return loginEnabled;
        }

        public String getClientId() {
            return clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public String getTokenInfoUrl() {
            return tokenInfoUrl;
        }

        public String getUserInfoUrl() {
            return userInfoUrl;
        }
    }

    public static class Facebook {
        private final boolean loginEnabled;
        private final String appId;
        private final String appSecret;
        private final String userInfoUrl;
        private final String apiVersion;

        private Facebook(boolean loginEnabled, String appId, String appSecret, String userInfoUrl, String apiVersion) {
            this.loginEnabled = loginEnabled;
            this.appId = appId;
            this.appSecret = appSecret;
            this.userInfoUrl = userInfoUrl;
            this.apiVersion = apiVersion;
        }

        public boolean isLoginEnabled() {
            return loginEnabled;
        }

        public String getAppId() {
            return appId;
        }

        public String getAppSecret() {
            return appSecret;
        }

        public String getUserInfoUrl() {
            return userInfoUrl;
        }

        public String getApiVersion() {
            return apiVersion;
        }
    }
}
