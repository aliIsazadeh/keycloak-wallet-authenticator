package com.w3auth.keycloak;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers the {@link W3AuthChallengeResourceProvider} under the realm-resource path
 * {@code /realms/{realm}/w3auth/}.
 *
 * <p>Registration is via
 * {@code META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory}.
 * The provider ID {@code "w3auth"} becomes the URL segment between the realm path and the
 * sub-paths declared on the resource class ({@code challenge}, {@code nonce/{nonce}}).
 */
public class W3AuthChallengeResourceProviderFactory implements RealmResourceProviderFactory {

    static final String PROVIDER_ID = "w3auth";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new W3AuthChallengeResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
