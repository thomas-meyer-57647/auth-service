package de.innologic.auth.social;

import de.innologic.auth.domain.enums.Provider;

public interface SocialProviderClient {
    Provider getProvider();

    SocialUserInfo fetchUserInfo(String token);
}
