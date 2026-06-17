package com.w3auth.backend.api;

import jakarta.validation.constraints.NotBlank;

record ChallengeRequest(@NotBlank String accountId) {
}
