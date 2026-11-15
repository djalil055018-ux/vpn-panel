INSERT INTO agent_releases(version,binary_sha256,installer_sha256,revoked) VALUES
('0.2.50','2bc5fc3a0528b39a9e23edddc1f3484930f836455838a3111f865f94db9a7259','451eaeb0dcf753b2b80d5ddd4deeee200bdd1beb3e9011e04bfc7bd0e34d344b',false),
('0.2.51','9179331f96e1053a3e823111072af5e291d194f887fc21cb2b3cde0f84b819a3','6414d3204cd1d5cdfd641ae3a9808f7cf68d210e2f6908aededc7696ada637fa',false)
ON CONFLICT(version) DO NOTHING;
