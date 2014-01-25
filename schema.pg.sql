DROP TABLE IF EXISTS test_results, srv_results, certificates, srv_certificates, certificate_subjects, tlsa_records, ciphers, srv_ciphers, srv_certificate_errors, public_servers CASCADE;

CREATE TABLE test_results
( test_id SERIAL UNIQUE
, server_name TEXT
, test_date TIMESTAMP
, type TEXT CHECK(type IN ('server','client')) NOT NULL
, version TEXT
, srv_dnssec_good BOOLEAN
, srv_dnssec_bogus BOOLEAN
);

CREATE TABLE srv_results
( srv_result_id SERIAL UNIQUE
, test_id INTEGER REFERENCES test_results(test_id)
, priority INTEGER
, weight INTEGER
, port INTEGER
, target TEXT
, requires_starttls BOOLEAN
, sslv2 BOOLEAN
, sslv3 BOOLEAN
, tlsv1 BOOLEAN
, tlsv1_1 BOOLEAN
, tlsv1_2 BOOLEAN
, compression TEXT
, reorders_ciphers BOOLEAN
, requires_peer_cert BOOLEAN
, trusted BOOLEAN
, valid_identity BOOLEAN
, cipher_score INTEGER
, certificate_score INTEGER
, keysize_score INTEGER
, protocol_score INTEGER
, total_score REAL
, grade TEXT
, done BOOLEAN
, tlsa_dnssec_good BOOLEAN
, tlsa_dnssec_bogus BOOLEAN
, a_aaaa_dnssec_good BOOLEAN
, a_aaaa_dnssec_bogus BOOLEAN
, warn_rc4_tls11 BOOLEAN
);

CREATE TABLE certificates
( certificate_id SERIAL UNIQUE
, pem TEXT
, notbefore TIMESTAMP
, notafter TIMESTAMP
, digest_sha1 TEXT
, digest_sha256 TEXT
, digest_sha512 TEXT UNIQUE
, subject_key_info TEXT
, subject_key_info_sha256 TEXT
, subject_key_info_sha512 TEXT
, rsa_bitsize INTEGER
, rsa_modulus TEXT
, debian_weak_key BOOLEAN
, sign_algorithm TEXT
, signed_by_id INTEGER
, trusted_root BOOLEAN
, crl_url TEXT
, ocsp_url TEXT
);

CREATE TABLE srv_certificates
( srv_certificates_id SERIAL UNIQUE
, srv_result_id INTEGER REFERENCES srv_results(srv_result_id)
, certificate_id INTEGER REFERENCES certificates(certificate_id)
, chain_index INTEGER
);

CREATE TABLE srv_certificate_errors
( srv_certificates_id INTEGER REFERENCES srv_certificates(srv_certificates_id)
, message TEXT
);

CREATE TABLE certificate_subjects
( certificate_subject_id SERIAL UNIQUE
, certificate_id INTEGER REFERENCES certificates(certificate_id)
, name TEXT
, oid TEXT
, value TEXT
);

CREATE UNIQUE INDEX certificate_subjects_unique ON certificate_subjects (certificate_id, oid, value);

CREATE TABLE tlsa_records
( tlsa_record_id SERIAL UNIQUE
, srv_result_id INTEGER REFERENCES srv_results(srv_result_id)
, usage INTEGER
, selector INTEGER
, match INTEGER
, data BYTEA
, verified BOOLEAN
);

CREATE TABLE ciphers
( cipher_id SERIAL UNIQUE
, openssl_name TEXT
, official_name TEXT
, bitsize INTEGER
, key_exchange TEXT
, authentication TEXT
, symmetric_alg TEXT
, hash_alg TEXT
, forward_secret BOOLEAN
, export BOOLEAN
, tls_version TEXT
);

CREATE TABLE srv_ciphers
( srv_result_id INTEGER REFERENCES srv_results(srv_result_id)
, cipher_id INTEGER  REFERENCES ciphers(cipher_id)
, cipher_index INTEGER
);

CREATE TABLE public_servers
( public_server_id SERIAL UNIQUE
, server_name TEXT UNIQUE
, founded INTEGER
, country TEXT
, url TEXT
, description TEXT
, admin TEXT
, vcard_rest TEXT
);

INSERT INTO "ciphers" VALUES(1,'NULL-MD5','TLS_RSA_WITH_NULL_MD5',0,'RSA','RSA','None','MD5',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(2,'NULL-SHA','TLS_RSA_WITH_NULL_SHA',0,'RSA','RSA','None','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(4,'RC4-MD5','SSL_CK_RC4_128_WITH_MD5',128,'RSA','RSA','RC4','MD5',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(5,'RC4-SHA','TLS_RSA_WITH_RC4_128_SHA',128,'RSA','RSA','RC4','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(6,'EXP-RC2-CBC-MD5','TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',40,'RSA','RSA','RC2','MD5',FALSE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(7,'IDEA-CBC-SHA','TLS_RSA_WITH_IDEA_CBC_SHA',128,'RSA','RSA','IDEA','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(8,'EXP-DES-CBC-SHA','TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',40,'RSA','RSA','DES','SHA-1',FALSE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(9,'DES-CBC-SHA','TLS_RSA_WITH_DES_CBC_SHA',56,'RSA','RSA','DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(10,'DES-CBC3-SHA','TLS_RSA_WITH_3DES_EDE_CBC_SHA',112,'RSA','RSA','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(17,'EXP-EDH-DSS-DES-CBC-SHA','TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',40,'DHE','DSS','DES','SHA-1',TRUE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(18,'EDH-DSS-DES-CBC-SHA','SSL_DHE_DSS_WITH_DES_CBC_SHA',56,'DHE','DSS','DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(19,'EDH-DSS-DES-CBC3-SHA','TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',112,'DHE','DSS','3DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(20,'EXP-EDH-RSA-DES-CBC-SHA','TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',40,'DHE','RSA','DES','SHA-1',TRUE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(21,'EDH-RSA-DES-CBC-SHA','TLS_DHE_RSA_WITH_DES_CBC_SHA',56,'DHE','RSA','DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(22,'EDH-RSA-DES-CBC3-SHA','TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',112,'DHE','RSA','3DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(23,'EXP-RC4-MD5','SSL_DH_anon_EXPORT_WITH_RC4_40_MD5',40,'DH','None','RC4','MD5',FALSE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(24,'ADH-RC4-MD5','TLS_DH_anon_WITH_RC4_128_MD5',128,'DH','None','RC4','MD5',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(25,'EXP-ADH-DES-CBC-SHA','TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',40,'DH','None','DES','SHA-1',FALSE,TRUE,'SSLv3');
INSERT INTO "ciphers" VALUES(26,'ADH-DES-CBC-SHA','TLS_DH_anon_WITH_DES_CBC_SHA',56,'DH','None','DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(27,'ADH-DES-CBC3-SHA','TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',112,'DH','None','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(47,'AES128-SHA','TLS_RSA_WITH_AES_128_CBC_SHA',128,'RSA','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(50,'DHE-DSS-AES128-SHA','TLS_DHE_DSS_WITH_AES_128_CBC_SHA',128,'DHE','DSS','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(51,'DHE-RSA-AES128-SHA','TLS_DHE_RSA_WITH_AES_128_CBC_SHA',128,'DHE','RSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(52,'ADH-AES128-SHA','TLS_DH_anon_WITH_AES_128_CBC_SHA',128,'DH','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(53,'AES256-SHA','TLS_RSA_WITH_AES_256_CBC_SHA',256,'RSA','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(56,'DHE-DSS-AES256-SHA','TLS_DHE_DSS_WITH_AES_256_CBC_SHA',256,'DHE','DSS','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(57,'DHE-RSA-AES256-SHA','TLS_DHE_RSA_WITH_AES_256_CBC_SHA',256,'DHE','RSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(58,'ADH-AES256-SHA','TLS_DH_anon_WITH_AES_256_CBC_SHA',256,'DH','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(59,'NULL-SHA256','TLS_RSA_WITH_NULL_SHA256',0,'RSA','RSA','None','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(60,'AES128-SHA256','TLS_RSA_WITH_AES_128_CBC_SHA256',128,'RSA','RSA','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(61,'AES256-SHA256','TLS_RSA_WITH_AES_256_CBC_SHA256',256,'RSA','RSA','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(64,'DHE-DSS-AES128-SHA256','TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',128,'DHE','DSS','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(65,'CAMELLIA128-SHA','TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',128,'RSA','RSA','CAMELLIA','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(68,'DHE-DSS-CAMELLIA128-SHA','TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',128,'DHE','DSS','CAMELLIA','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(69,'DHE-RSA-CAMELLIA128-SHA','TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',128,'DHE','RSA','CAMELLIA','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(70,'ADH-CAMELLIA128-SHA','TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',128,'DH','None','CAMELLIA','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(103,'DHE-RSA-AES128-SHA256','TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',128,'DHE','RSA','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(106,'DHE-DSS-AES256-SHA256','TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',256,'DHE','DSS','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(107,'DHE-RSA-AES256-SHA256','TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',256,'DHE','RSA','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(108,'ADH-AES128-SHA256','TLS_DH_anon_WITH_AES_128_CBC_SHA256',128,'DH','None','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(109,'ADH-AES256-SHA256','TLS_DH_anon_WITH_AES_256_CBC_SHA256',256,'DH','None','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(132,'CAMELLIA256-SHA','TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',256,'RSA','RSA','CAMELLIA','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(135,'DHE-DSS-CAMELLIA256-SHA','TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',256,'DHE','DSS','CAMELLIA','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(136,'DHE-RSA-CAMELLIA256-SHA','TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',256,'DHE','RSA','CAMELLIA','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(137,'ADH-CAMELLIA256-SHA','TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',256,'DH','None','CAMELLIA','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(138,'PSK-RC4-SHA','TLS_PSK_WITH_RC4_128_SHA',128,'PSK','PSK','RC4','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(139,'PSK-3DES-EDE-CBC-SHA','TLS_PSK_WITH_3DES_EDE_CBC_SHA',112,'PSK','PSK','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(140,'PSK-AES128-CBC-SHA','TLS_PSK_WITH_AES_128_CBC_SHA',128,'PSK','PSK','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(141,'PSK-AES256-CBC-SHA','TLS_PSK_WITH_AES_256_CBC_SHA',256,'PSK','PSK','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(150,'SEED-SHA','TLS_RSA_WITH_SEED_CBC_SHA',128,'RSA','RSA','SEED','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(153,'DHE-DSS-SEED-SHA','TLS_DHE_DSS_WITH_SEED_CBC_SHA',128,'DHE','DSS','SEED','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(154,'DHE-RSA-SEED-SHA','TLS_DHE_RSA_WITH_SEED_CBC_SHA',128,'DHE','RSA','SEED','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(155,'ADH-SEED-SHA','TLS_DH_anon_WITH_SEED_CBC_SHA',128,'DH','None','SEED','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(156,'AES128-GCM-SHA256','TLS_RSA_WITH_AES_128_GCM_SHA256',128,'RSA','RSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(157,'AES256-GCM-SHA384','TLS_RSA_WITH_AES_256_GCM_SHA384',256,'RSA','RSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(158,'DHE-RSA-AES128-GCM-SHA256','TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',128,'DHE','RSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(159,'DHE-RSA-AES256-GCM-SHA384','TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',256,'DHE','RSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(162,'DHE-DSS-AES128-GCM-SHA256','TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',128,'DHE','DSS','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(163,'DHE-DSS-AES256-GCM-SHA384','TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',256,'DHE','DSS','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(166,'ADH-AES128-GCM-SHA256','TLS_DH_anon_WITH_AES_128_GCM_SHA256',128,'DH','None','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(167,'ADH-AES256-GCM-SHA384','TLS_DH_anon_WITH_AES_256_GCM_SHA384',256,'DH','None','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49153,'ECDH-ECDSA-NULL-SHA','TLS_ECDH_ECDSA_WITH_NULL_SHA',0,'ECDH','ECDSA','None','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49154,'ECDH-ECDSA-RC4-SHA','TLS_ECDH_ECDSA_WITH_RC4_128_SHA',128,'ECDH','ECDSA','RC4','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49155,'ECDH-ECDSA-DES-CBC3-SHA','TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',112,'ECDH','ECDSA','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49156,'ECDH-ECDSA-AES128-SHA','TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',128,'ECDH','ECDSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49157,'ECDH-ECDSA-AES256-SHA','TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',256,'ECDH','ECDSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49158,'ECDHE-ECDSA-NULL-SHA','TLS_ECDHE_ECDSA_WITH_NULL_SHA',0,'ECDHE','ECDSA','None','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49159,'ECDHE-ECDSA-RC4-SHA','TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',128,'ECDHE','ECDSA','RC4','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49160,'ECDHE-ECDSA-DES-CBC3-SHA','TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',112,'ECDHE','ECDSA','3DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49161,'ECDHE-ECDSA-AES128-SHA','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',128,'ECDHE','ECDSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49162,'ECDHE-ECDSA-AES256-SHA','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',256,'ECDHE','ECDSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49163,'ECDH-RSA-NULL-SHA','TLS_ECDH_RSA_WITH_NULL_SHA',0,'ECDH','RSA','None','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49164,'ECDH-RSA-RC4-SHA','TLS_ECDH_RSA_WITH_RC4_128_SHA',128,'ECDH','RSA','RC4','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49165,'ECDH-RSA-DES-CBC3-SHA','TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',112,'ECDH','RSA','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49166,'ECDH-RSA-AES128-SHA','TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',128,'ECDH','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49167,'ECDH-RSA-AES256-SHA','TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',256,'ECDH','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49168,'ECDHE-RSA-NULL-SHA','TLS_ECDHE_RSA_WITH_NULL_SHA',0,'ECDHE','RSA','None','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49169,'ECDHE-RSA-RC4-SHA','TLS_ECDHE_RSA_WITH_RC4_128_SHA',128,'ECDHE','RSA','RC4','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49170,'ECDHE-RSA-DES-CBC3-SHA','TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',112,'ECDHE','RSA','3DES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49171,'ECDHE-RSA-AES128-SHA','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',128,'ECDHE','RSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49172,'ECDHE-RSA-AES256-SHA','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',256,'ECDHE','RSA','AES','SHA-1',TRUE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49173,'AECDH-NULL-SHA','TLS_ECDH_anon_WITH_NULL_SHA',0,'ECDH','None','None','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49174,'AECDH-RC4-SHA','TLS_ECDH_anon_WITH_RC4_128_SHA',128,'ECDH','None','RC4','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49175,'AECDH-DES-CBC3-SHA','TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',112,'ECDH','None','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49176,'AECDH-AES128-SHA','TLS_ECDH_anon_WITH_AES_128_CBC_SHA',128,'ECDH','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49177,'AECDH-AES256-SHA','TLS_ECDH_anon_WITH_AES_256_CBC_SHA',256,'ECDH','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49178,'SRP-3DES-EDE-CBC-SHA','TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',112,'SRP','None','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49179,'SRP-RSA-3DES-EDE-CBC-SHA','TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',112,'SRP','RSA','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49180,'SRP-DSS-3DES-EDE-CBC-SHA','TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',112,'SRP','DSS','3DES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49181,'SRP-AES-128-CBC-SHA','TLS_SRP_SHA_WITH_AES_128_CBC_SHA',128,'SRP','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49182,'SRP-RSA-AES-128-CBC-SHA','TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',128,'SRP','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49183,'SRP-DSS-AES-128-CBC-SHA','TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',128,'SRP','DSS','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49184,'SRP-AES-256-CBC-SHA','TLS_SRP_SHA_WITH_AES_256_CBC_SHA',256,'SRP','None','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49185,'SRP-RSA-AES-256-CBC-SHA','TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',256,'SRP','RSA','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49186,'SRP-DSS-AES-256-CBC-SHA','TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',256,'SRP','DSS','AES','SHA-1',FALSE,FALSE,'SSLv3');
INSERT INTO "ciphers" VALUES(49187,'ECDHE-ECDSA-AES128-SHA256','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',128,'ECDHE','ECDSA','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49188,'ECDHE-ECDSA-AES256-SHA384','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',256,'ECDHE','ECDSA','AES','SHA-384',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49189,'ECDH-ECDSA-AES128-SHA256','TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',128,'ECDH','ECDSA','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49190,'ECDH-ECDSA-AES256-SHA384','TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',256,'ECDH','ECDSA','AES','SHA-384',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49191,'ECDHE-RSA-AES128-SHA256','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',128,'ECDHE','RSA','AES','SHA-256',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49192,'ECDHE-RSA-AES256-SHA384','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',256,'ECDHE','RSA','AES','SHA-384',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49193,'ECDH-RSA-AES128-SHA256','TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',128,'ECDH','RSA','AES','SHA-256',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49194,'ECDH-RSA-AES256-SHA384','TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',256,'ECDH','RSA','AES','SHA-384',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49195,'ECDHE-ECDSA-AES128-GCM-SHA256','TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',128,'ECDHE','ECDSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49196,'ECDHE-ECDSA-AES256-GCM-SHA384','TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',256,'ECDHE','ECDSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49197,'ECDH-ECDSA-AES128-GCM-SHA256','TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',128,'ECDH','ECDSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49198,'ECDH-ECDSA-AES256-GCM-SHA384','TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',256,'ECDH','ECDSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49199,'ECDHE-RSA-AES128-GCM-SHA256','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',128,'ECDHE','RSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49200,'ECDHE-RSA-AES256-GCM-SHA384','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',256,'ECDHE','RSA','AESGCM','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49201,'ECDH-RSA-AES128-GCM-SHA256','TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',128,'ECDH','RSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(49202,'ECDH-RSA-AES256-GCM-SHA384','TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',256,'ECDH','RSA','AESGCM','AEAD',FALSE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(65664,'RC4-MD5','SSL_CK_RC4_128_WITH_MD5',128,'RSA','RSA','RC4','MD5',FALSE,FALSE,'SSLv2');
INSERT INTO "ciphers" VALUES(131200,'EXP-RC4-MD5','SSL_CK_RC4_128_EXPORT40_WITH_MD5',40,'RSA','RSA','RC4','MD5',FALSE,TRUE,'SSLv2');
INSERT INTO "ciphers" VALUES(196736,'RC2-CBC-MD5','SSL_CK_RC2_128_CBC_WITH_MD5',128,'RSA','RSA','RC2','MD5',FALSE,FALSE,'SSLv2');
INSERT INTO "ciphers" VALUES(262272,'EXP-RC2-CBC-MD5','TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',40,'RSA','RSA','RC2','MD5',FALSE,TRUE,'SSLv2');
INSERT INTO "ciphers" VALUES(327808,'IDEA-CBC-MD5','SSL_CK_IDEA_128_CBC_WITH_MD5',128,'RSA','RSA','IDEA','MD5',FALSE,FALSE,'SSLv2');
INSERT INTO "ciphers" VALUES(393280,'DES-CBC-MD5','SSL_CK_DES_64_CBC_WITH_MD5',56,'RSA','RSA','DES','MD5',FALSE,FALSE,'SSLv2');
INSERT INTO "ciphers" VALUES(458944,'DES-CBC3-MD5','SSL_CK_DES_192_EDE3_CBC_WITH_MD5',112,'RSA','RSA','3DES','MD5',FALSE,FALSE,'SSLv2');

INSERT INTO "ciphers" VALUES(52243,'ECDHE-RSA-CHACHA20-POLY1305','TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',256,'ECDHE','RSA','ChaCha20-Poly1305','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(52244,'ECDHE-ECDSA-CHACHA20-POLY1305','TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',256,'ECDHE','ECDSA','ChaCha20-Poly1305','AEAD',TRUE,FALSE,'TLSv1.2');
INSERT INTO "ciphers" VALUES(52245,'DHE-RSA-CHACHA20-POLY1305','TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA25',256,'DHE','RSA','ChaCha20-Poly1305','AEAD',TRUE,FALSE,'TLSv1.2');


GRANT ALL PRIVILEGES ON TABLE test_results, srv_results, certificates, srv_certificates, certificate_subjects, tlsa_records, ciphers, srv_ciphers, srv_certificate_errors, public_servers TO xmppoke;

GRANT ALL PRIVILEGES ON SEQUENCE test_results_test_id_seq, srv_results_srv_result_id_seq, srv_results_srv_result_id_seq, tlsa_records_tlsa_record_id_seq, certificates_certificate_id_seq, certificate_subjects_certificate_subject_id_seq, srv_certificates_srv_certificates_id_seq TO xmppoke;

INSERT INTO "public_servers" (server_name, founded, country) VALUES ('0nl1ne.at', 2007, 'AT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('blah.im', 2009, 'AT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('boese-ban.de', 2008, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('brauchen.info', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('ch3kr.net', 2013, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('chatme.im', 2010, 'IT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('chrome.pl', 2001, 'PL');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('climm.org', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('coderollers.com', 2010, 'RO');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('codingteam.net', 2007, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('comm.unicate.me', 2012, 'UK');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('creep.im', 2012, 'RU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('deshalbfrei.org', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('draugr.de', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('einfachjabber.de', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('forumanalogue.fr', 2010, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('im.apinc.org', 2004, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('im.flosoft.biz', 2004, 'EU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('internet-exception.de', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('is-a-furry.org', 2013, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabb3r.net', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber-br.org', 2005, 'BR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber-hosting.de', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.at', 2010, 'AT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.chaotic.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.co.nz', 2009, 'NZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.cz', 2001, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.de', 2012, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.earth.li', 2000, 'UK');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.etighichat.com', 2012, 'NG');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.fourecks.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.gate31.net', 2012, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.hot-chilli.net', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.i-pobox.net', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.iitsp.com', 2008, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.loudas.com', 2009, 'NZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.me', 2010, 'EU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.meta.net.nz', 2003, 'NZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.minus273.org', 2002, 'BG');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.no-sense.net', 2009, 'NL');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.no', 2004, 'NO');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.org', 1999, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.rootbash.com', 2006, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.rueckgr.at', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.scha.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.schnied.net', 2006, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.second-home.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.smash-net.org', 2012, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.sow.as', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.theforest.us', 2010, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.tmkis.com', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabber.yeahnah.co.nz', 2009, 'NZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabberafrica.org', 2013, 'ZA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabberd.eu', 2009, 'RU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabberes.org', 2003, 'ES');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabberpl.org', 2002, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabbim.com', 2005, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabbim.cz', 2005, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabbim.hu', 2013, 'HU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabbim.pl', 2005, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabbim.sk', 2005, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabin.org', 2009, 'ID');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabme.de', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jabster.pl', 2004, 'PL');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jaim.at', 2004, 'AT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jappix.com', 2010, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('jisshi.com', 2012, 'IT');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('labnote.org', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('lightwitch.org', 2009, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('limun.org', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('lsd-25.ru', 2008, 'RU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('macjabber.de', 2006, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('mayplaces.com', 2010, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('miqote.com', 2012, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('na-di.de', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('neko.im', 2008, 'NO');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('netmindz.net', 2002, 'UK');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('njs.netlab.cz', 2001, 'CZ');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('palemoon.net', 2013, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('palita.net', 2008, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('pandion.im', 2009, 'EU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('pidgin.su', 2009, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('programmer-art.org', 2008, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('prosody.de', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('richim.org', 2009, 'UA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('rkquery.de', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('sss.chaoslab.ru', 2008, 'UA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('sternenschweif.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('suchat.org', 2012, 'ES');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('swissjabber.ch', 2002, 'CH');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('swissjabber.de', 2002, 'CH');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('swissjabber.eu', 2002, 'CH');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('swissjabber.li', 2002, 'CH');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('swissjabber.org', 2002, 'CH');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('tcweb.org', 2007, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('tekst.me', 2010, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('thiessen.im', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('thiessen.it', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('thiessen.org', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('tigase.im', 2010, 'EU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('twattle.net', 2012, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('ubuntu-jabber.de', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('ubuntu-jabber.net', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('univers-libre.net', 2009, 'FR');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('uprod.biz', 2013, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('verdammung.org', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('wtfismyip.com', 2012, 'USA');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('xabber.de', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('xmpp-hosting.de', 2005, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('xmpp.jp', 2009, 'JP');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('xmpp.ru.net', 2011, 'RU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('xmppnet.de', 2003, 'DE');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('zauris.ru', 2011, 'RU');
INSERT INTO "public_servers" (server_name, founded, country) VALUES ('zsim.de', 2009, 'DE');
