/**
 * Composition root: wires use cases (core) to infrastructure adapters (Redis, Postgres)
 * and supplies production singletons (e.g. {@link java.time.Clock}). This is the only
 * place that may import both core and infrastructure packages at once.
 */
package com.w3auth.backend.config;
