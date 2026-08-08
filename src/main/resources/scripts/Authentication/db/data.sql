-- Level 1: SQL Injection
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- Real password: 'v9K#2mLp!8zQ' - fixed: stored as a BCrypt hash instead of plaintext, and the
-- LEVEL_2 code path no longer logs the submitted password (see AuthLoginService#authenticate).
INSERT INTO auth_users VALUES (2, 'admin_logs', '$2a$10$kcDYR9xAS1wlj9jcdXMZU.uo1G.XpaJYQBiVl3ySm.QOFrlMfq.H2', NULL, 'BCRYPT', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: Plaintext Storage
-- Real password: 'b7X$4nRj-6mW' - fixed: stored as a BCrypt hash instead of plaintext so a
-- database/log leak no longer exposes a directly reusable credential.
INSERT INTO auth_users VALUES (3, 'admin_plain', '$2a$10$WMP3HLFOubUM9pezy9OZd.b5keb9cX.n7taFDTlmmvSnptpdiHGa2', NULL, 'BCRYPT', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: fixed - was unsalted MD5 (f2C@9tYk*1hP), trivially reversible via rainbow tables.
-- Now stored as a salted, slow BCrypt hash.
INSERT INTO auth_users VALUES (4, 'admin_md5', '$2a$10$sUEniOlt2X8Lqym3y7N5P.kswBr6erir/hWXUzZju3PK621ByEmCu', NULL, 'BCRYPT', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: fixed - was unsalted SHA-1 (x5B&3gHq+7vS), also rainbow-table crackable. Now BCrypt.
INSERT INTO auth_users VALUES (5, 'admin_sha1', '$2a$10$j4aAz3sq9DMZQKtiMsmReubzuQZW6PSjgMd1lunKppLcuOnJZ1kdW', NULL, 'BCRYPT', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: fixed - was unsalted SHA-256 (m8D!4kLr#2jZ); a fast, unsalted general-purpose digest
-- is not an acceptable password hash regardless of output size. Now BCrypt.
INSERT INTO auth_users VALUES (6, 'admin_sha256', '$2a$10$yyI4BSt21ASTRCF5GRRR2OcryloY2R.ISQdcafXlTHHQk94W8qJ7K', NULL, 'BCRYPT', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk)
INSERT INTO auth_users VALUES (7, 'admin_enum', '71ad23cc508b5658f0bc21d8323f55521be98ca951e83a4a4d15641a3ca2b8a4', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: fixed - the account used to hold 'password123', a top-10 rockyou.txt entry: BCrypt
-- slows a guess down but cannot save a secret that a short dictionary already contains. The
-- credential itself was the flaw, so it is now a high-entropy, non-dictionary password (bcrypt
-- cost 12) alongside the account lockout added in AuthenticationVulnerability#level8WeakPassword.
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$12$WsjsWxzoU13IqxNxG9Evxu5vvZgsLfeTumzc4yMb5dY5G4S4tRj8a', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: fixed - two things were wrong here. The stored hash carried a cost factor of 4,
-- roughly a thousand times cheaper to attack than a modern default, so a database dump could be
-- cracked offline in a reasonable time; and the credential itself was 'sunshine', a rockyou.txt
-- dictionary word that no work factor can rescue since the search space is a few thousand
-- candidates either way. Both are fixed: bcrypt cost 12 over a high-entropy, non-dictionary
-- password (algorithm normalized to BCRYPT since the stored hash's own cost factor, not the
-- enum label, is what BCryptPasswordEncoder#matches actually verifies against).
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$12$j.ANePv/UWftLwdM/7TbZO20QPzRbxm2Y1lsTsv3PWoWFHZttwH3K', NULL, 'BCRYPT', 10, 'admin_lowcost@example.com', 'ADMIN');
