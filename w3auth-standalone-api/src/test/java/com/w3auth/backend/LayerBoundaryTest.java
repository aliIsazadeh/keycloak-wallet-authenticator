package com.w3auth.backend;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Architecture decision: core packages (identity, challenge, verification, session, usecase)
 * must remain plain Java — no Spring, JPA, Hibernate, Redis, or infrastructure imports.
 * This keeps domain logic testable without a container and enforces the port/adapter split.
 * See CLAUDE.md "Locked architecture decisions" and docs/ARCHITECTURE.md "Layer boundaries".
 */
class LayerBoundaryTest {

    private static final String[] CORE_PACKAGES = {
        "com.w3auth.backend.identity..",
        "com.w3auth.backend.challenge..",
        "com.w3auth.backend.verification..",
        "com.w3auth.backend.session..",
        "com.w3auth.backend.usecase.."
    };

    private static final String[] FORBIDDEN_PACKAGES = {
        "org.springframework..",
        "jakarta.persistence..",
        "org.hibernate..",
        "io.lettuce..",
        "com.w3auth.backend.infrastructure.."
    };

    @Test
    void corePackagesMustNotImportFrameworkOrInfrastructure() {
        // Import only production classes so test helpers in the same packages don't interfere.
        JavaClasses classes = new ClassFileImporter()
            .importPackages("com.w3auth.backend");

        // Fail fast if the importer found nothing — a vacuous pass is worse than no guard.
        if (classes.isEmpty()) {
            throw new AssertionError(
                "ArchUnit found zero classes in com.w3auth.backend — check the classpath.");
        }

        ArchRule rule = noClasses()
            .that().resideInAnyPackage(CORE_PACKAGES)
            .should().dependOnClassesThat().resideInAnyPackage(FORBIDDEN_PACKAGES)
            .because("core packages must stay framework-free (CLAUDE.md locked architecture decision #1-#5)");

        rule.check(classes);
    }
}
