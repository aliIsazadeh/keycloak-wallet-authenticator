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
 * Keycloak Authenticator Factory to register and configure the {@link W3AuthAuthenticator}.
 */
public class W3AuthAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "w3auth-authenticator";
    private static final W3AuthAuthenticator SINGLETON = new W3AuthAuthenticator();

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(
            new ProviderConfigProperty(
                    "expected-domain",
                    "Expected Domain",
                    "The domain name that must match the domain parameter in SIWE/SIWS messages.",
                    ProviderConfigProperty.STRING_TYPE,
                    "localhost"
            ),
            new ProviderConfigProperty(
                    "expected-uri",
                    "Expected URI",
                    "The URI string that must match the URI parameter in SIWE/SIWS messages.",
                    ProviderConfigProperty.STRING_TYPE,
                    "http://localhost:8080"
            ),
            new ProviderConfigProperty(
                    "ethereum-rpc-url",
                    "Ethereum RPC URL",
                    "The JSON-RPC URL of an Ethereum node used to perform EIP-1271/EIP-6492 smart-contract wallet verifications. If left empty, smart-contract wallets will be disabled.",
                    ProviderConfigProperty.STRING_TYPE,
                    ""
            )
    );

    @Override
    public String getDisplayType() {
        return "Web3 Wallet Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "w3auth";
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return "Enables users to sign in with their Web3 wallets (SIWE/SIWS) and verifies signatures against browser-injected wallets.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
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
