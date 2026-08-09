-- Table is seeded by CryptographicFailuresSeeder in vulnerability.service.cryptographicFailures

DROP TABLE IF EXISTS cryptographic_failures_vault;

CREATE TABLE cryptographic_failures_vault (
    level INT PRIMARY KEY ,
    password VARCHAR(500),
    algorithm VARCHAR(50)
);

-- Application user has full access (for functional purposes)
GRANT ALL ON cryptographic_failures_vault TO application;

-- This table used to also provision a standing, read-only account with a hardcoded password
-- (CWE-798) granting direct SELECT access to every level's stored secret, bypassing whatever
-- protection the application layer applied. That account has been removed; the application
-- user above retains the access it actually needs, and nothing else can read this table.