package com.w3auth.backend.usecase;

import com.w3auth.backend.session.RefreshTokenStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LogoutTest {

    @Mock
    RefreshTokenStore store;

    @InjectMocks
    Logout logout;

    @Test
    void execute_delegatesToRevokeFamilyByToken() {
        String raw = "some-raw-refresh-token";

        logout.execute(raw);

        verify(store, times(1)).revokeFamilyByToken(raw);
    }
}
