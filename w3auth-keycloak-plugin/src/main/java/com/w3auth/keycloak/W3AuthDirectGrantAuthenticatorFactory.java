package com.w3auth.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Keycloak Authenticator Factory to register and configure the {@link W3AuthDirectGrantAuthenticator}.
 *
 * <p>Bind an execution of this authenticator into a realm's {@code direct_grant} flow (or a
 * client-scoped override of it, via {@code ClientRepresentation.authenticationFlowBindingOverrides})
 * to accept native wallet logins through the OIDC token endpoint. No config properties: unlike the
 * browser authenticator, this flow reads its domain/uri/rpcUrl from realm attributes (the same ones
 * the Slice A challenge endpoint uses), not from per-execution {@code AuthenticatorConfig}.
 */
public class W3AuthDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "w3auth-direct-grant-authenticator";
    private static final W3AuthDirectGrantAuthenticator SINGLETON = new W3AuthDirectGrantAuthenticator();

    @Override
    public String getDisplayType() {
        return "Web3 Wallet Direct Grant";
    }

    @Override
    public String getReferenceCategory() {
        return "w3auth";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validates a Web3 wallet signature (SIWE/SIWS) submitted via the OIDC direct-grant "
                + "(grant_type=password) token endpoint and issues real Keycloak tokens for native clients.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
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

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
