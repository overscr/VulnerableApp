-- Level 1: SQL Injection
-- Real password: 'not_needed_for_sqli'
INSERT INTO auth_users VALUES (1, 'admin_sqli', 'not_needed_for_sqli', NULL, 'PLAIN', 1, 'admin_sqli@example.com', 'ADMIN');

-- Level 2: Sensitive Data Logging
-- The controller no longer routes this level through a method that logs the raw password, but
-- the credential store itself must not compound that by keeping the password in the clear either.
-- Bcrypt hash (cost 12) for '5B&YbR7AVw!+WxqZkC'
INSERT INTO auth_users VALUES (2, 'admin_logs', '$2a$12$GTOs7yu124IKkbgbJWKGWO.DFdzz0QwI37VcjmpGb0fJmdzogS3bS', NULL, 'BCRYPT', 2, 'admin_logs@example.com', 'ADMIN');

-- Level 3: was Plaintext Storage - a leaked/dumped database handed over every credential verbatim.
-- Bcrypt hash (cost 12) for '-YDTB6Z*tksjdbS5rF'
INSERT INTO auth_users VALUES (3, 'admin_plain', '$2a$12$t2/KkQJgvZSyMS5fpYGppuilGs.Ti0i3rYJH2cTFzyz6jlbjqvnsa', NULL, 'BCRYPT', 3, 'admin_plain@example.com', 'ADMIN');

-- Level 4: was MD5 - fast and unsalted, so a dump is a wordlist run (hashcat -m 0) away from plaintext.
-- Bcrypt hash (cost 12) for '6Erm-aFLlNF@qU4JhW'
INSERT INTO auth_users VALUES (4, 'admin_md5', '$2a$12$bz/.A9rOaiUJ5SJfTwdPCuO.7uvOk5Qw.XBsu0bFa1BGThNAhOdt2', NULL, 'BCRYPT', 4, 'admin_md5@example.com', 'ADMIN');

-- Level 5: was SHA-1 - deprecated, and just as fast/unsalted as MD5 (hashcat -m 100).
-- Bcrypt hash (cost 12) for 'RgVDLyeNW@d6mU=Mc2'
INSERT INTO auth_users VALUES (5, 'admin_sha1', '$2a$12$qSQetcO.qC6OvBsTgE24uuAxbBFdOMeLrpniGquFp4jYQxyrQowXe', NULL, 'BCRYPT', 5, 'admin_sha1@example.com', 'ADMIN');

-- Level 6: was unsalted SHA-256 - a sound hash but a bad password hash: no salt means one
-- precomputed table covers every account, and its speed is what makes such a table cheap to build.
-- Bcrypt hash (cost 12) for 'MxKhFVn!@R&P&fyu91'
INSERT INTO auth_users VALUES (6, 'admin_sha256', '$2a$12$NmC1ioPDcigUv4qleIzBAeZWdAgC9QEP55O27XSi150TEHCsq0Nby', NULL, 'BCRYPT', 6, 'admin_sha256@example.com', 'ADMIN');

-- Level 7: Salted SHA-256 (q1W%6nTp^8vM with Salt s9A#2zLk)
INSERT INTO auth_users VALUES (7, 'admin_enum', '71ad23cc508b5658f0bc21d8323f55521be98ca951e83a4a4d15641a3ca2b8a4', 's9A#2zLk', 'SHA256', 7, 'admin_enum@example.com', 'ADMIN');

-- Level 8: was Bcrypt over 'password123', a top-10 rockyou entry. Bcrypt slows a guess down but
-- cannot rescue a secret that a short dictionary already contains - the credential was the flaw.
-- Bcrypt hash (cost 12) for 'hTEvWf=fqK1rsybth9'
INSERT INTO auth_users VALUES (8, 'admin_weak', '$2a$12$MMsNaMj8KUp4jo8g6usAs.kPlbUuPGKtO6DnrwrzkYm1/kktXe9t6', NULL, 'BCRYPT', 8, 'admin_weak@example.com', 'ADMIN');

-- Level 9: Secure (Bcrypt + Generic Error) (9fG#2hJk*LmN!8qR)
-- Bcrypt hash for '9fG#2hJk*LmN!8qR'
INSERT INTO auth_users VALUES (9, 'admin_secure', '$2a$10$1WiFUNqUY/vHTzR2QtuMQuzCLK3aZEdjEUpqS4msXOevaCz7Wobe.', NULL, 'BCRYPT', 9, 'admin_secure@example.com', 'ADMIN');

-- Level 10: two things were wrong here - a cost-4 hash (hashcat -m 3200 territory, roughly a
-- thousand times cheaper to attack than a modern default) AND the credential itself was
-- 'sunshine', a rockyou dictionary word. Raising the work factor alone does not fix a hash whose
-- search space is a few thousand candidates either way, so both are replaced.
-- Bcrypt hash (cost 12) for '#t+ukGe^S&&KmipbGJ'
INSERT INTO auth_users VALUES (10, 'admin_lowcost', '$2a$12$At8RQPTC8kX6Brdt0iIkeu6GW461dFAmsouG7JdvSbrO.XHeJygVS', NULL, 'BCRYPT_LOW_ITERATION', 10, 'admin_lowcost@example.com', 'ADMIN');
