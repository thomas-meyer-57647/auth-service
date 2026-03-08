package de.innologic.auth.social;

public class SocialUserInfo {

    private final String providerSubject;
    private final String email;

    public SocialUserInfo(String providerSubject, String email) {
        this.providerSubject = providerSubject;
        this.email = email;
    }

    public String getProviderSubject() {
        return providerSubject;
    }

    public String getEmail() {
        return email;
    }
}
