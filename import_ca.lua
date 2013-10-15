local ssl = require "ssl"
local dbi = require "DBI"
local date = require "3rdparty/date"
require "certs"

local sha512 = require("util.hashes").sha512;
local sha256 = require("util.hashes").sha256;

dbh = assert(dbi.Connect("PostgreSQL", "xmppoke", "xmppoke", "xmppoke", "localhost", 5433));

local function execute_and_get_id(q, ...)
    local stm = assert(dbh:prepare(q .. " RETURNING *;"));
    
    local _, err = stm:execute(...);

    if err then return nil, err end
    
    dbh:commit();

    local result = stm:fetch();

    print(result);

    if result then
        return result[1];
    else
        return nil, "Not found";
    end
end

local function insert_cert(dbh, cert)
    local stm = assert(dbh:prepare("SELECT certificate_id FROM certificates WHERE pem = ?"));
    local pem = cert:pem();
    assert(stm:execute(pem));

    local cert_id = nil;

    local results = stm:fetch();

    if not results or #results == 0 then
        local q = "INSERT INTO certificates ( pem, notbefore, notafter, digest_sha1, digest_sha256," ..
                                            " digest_sha512, rsa_bitsize, rsa_modulus," ..
                                            " debian_weak_key, sign_algorithm, trusted_root, crl_url, ocsp_url," ..
                                            " subject_key_info, subject_key_info_sha256, subject_key_info_sha512)" ..
                                        " SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM certificates WHERE digest_sha512 = ?)";

        local spki = cert:spki();
        cert_id, err = execute_and_get_id(q, pem, date(cert:notbefore()):fmt("%Y-%m-%d %T"), date(cert:notafter()):fmt("%Y-%m-%d %T"), cert:digest("sha1"), cert:digest("sha256"),
                           cert:digest("sha512"), cert:bits(), cert:modulus(),
                           debian_weak_key(cert), cert:signature_alg(), true, cert:crl(), cert:ocsp(),
                           hex(spki), hex(sha256(spki)), hex(sha512(spki)), cert:digest("sha512"));

        print(cert_id);

        -- A race condition, great. Lets retry the lookup.
        if err then
        	print(err);
            assert(stm:execute(pem));

            dbh:commit();

            cert_id = stm:fetch()[1];
        else
            stm = assert(dbh:prepare("INSERT INTO certificate_subjects (certificate_id, name, oid, value) VALUES (?, ?, ?, ?)"));

            for k,v in pairs(cert:subject()) do
                assert(stm:execute(cert_id, v.name, v.oid, v.value));
            end
        end
    else
        cert_id = results[1];
    end

    return cert_id;
end

local file = io.open("ca.pem", "r");

local str = file:read("*a");

file:close();

for cert in str:gmatch("-----BEGIN CERTIFICATE-----\n[^-]*\n-----END CERTIFICATE-----\n") do
	print(ssl.x509.load(cert));
	assert(insert_cert(dbh, ssl.x509.load(cert)));
end

dbh:commit();