package org.sasanlabs.configuration;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

/**
 * Runs all {@link ModuleSeeder} implementations while the application context is still starting
 * up, so every module's table is populated before the embedded server opens its port.
 *
 * <p>This used to hang off {@code ApplicationReadyEvent}, which Spring Boot fires only after the
 * web server is already listening. That left a startup window in which the server was accepting
 * connections against tables that had not been seeded yet - any request landing in that window
 * would either 404/500 against empty data or, for endpoints with a fallback path, be served an
 * unseeded/default state instead of the intended one. Seeding as part of singleton
 * initialization instead means it always completes before the port is bound, so there is no
 * window in which a live request can observe an unseeded table.
 */
@Component
public class DatabaseSeeder implements SmartInitializingSingleton {

    private static final transient Logger LOGGER = LogManager.getLogger(DatabaseSeeder.class);

    //  Finds every @Component that implements ModuleSeeder
    private final List<ModuleSeeder> seeders;

    public DatabaseSeeder(List<ModuleSeeder> seeders) {
        this.seeders = seeders;
    }

    @Override
    public void afterSingletonsInstantiated() {
        LOGGER.info("Starting Global Database Seeding");

        for (ModuleSeeder seeder : seeders) {
            try {
                if (!seeder.isSeeded()) {
                    seeder.seed();
                    LOGGER.info(
                            "{} seeded module: {} (Table: {})",
                            seeder.toString(),
                            seeder.getModuleName(),
                            seeder.getModuleTable());
                }
            } catch (Exception e) {
                LOGGER.error(
                        "{} failed to seed module: {} (Table: {}). Aborting startup.",
                        seeder.toString(),
                        seeder.getModuleName(),
                        seeder.getModuleTable(),
                        e);
                // afterSingletonsInstantiated() has no checked-exception signature to
                // propagate through, but a module that fails to seed must still abort
                // startup rather than let the app come up with a half-seeded table.
                throw new IllegalStateException(
                        "Seeding failed for module: " + seeder.getModuleName(), e);
            }
        }

        LOGGER.info("Seeding complete. Processed {} modules", seeders.size());
    }
}
