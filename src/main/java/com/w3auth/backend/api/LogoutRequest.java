package com.w3auth.backend.api;

import jakarta.validation.constraints.NotBlank;

record LogoutRequest(@NotBlank String refreshToken) {}
