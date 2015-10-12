local sha256 = require("util.hashes").sha256;
local sha512 = require("util.hashes").sha512;

function execute_and_get_id(dbh, q, ...)
    local stm = assert(dbh:prepare(q .. " RETURNING *;"));
    
    local _, err = stm:execute(...);

    if err then return nil, err end
    
    dbh:commit();

    local result = stm:fetch();

    if result then
        return result[1];
    else
        return nil, "Not found";
    end
end

function insert_cert(dbh, cert, srv_result_id, chain_index, errors)
    local stm = assert(dbh:prepare("SELECT certificate_id FROM certificates WHERE pem = ?"));
    local pem = cert:pem();
    assert(stm:execute(pem));

    dbh:commit();

    local cert_id = nil;

    local results = stm:fetch();

    if not results or #results == 0 then
        local q = "INSERT INTO certificates ( pem, notbefore, notafter, digest_sha1, digest_sha256," ..
                                            " digest_sha512, pubkey_bitsize, pubkey_type, rsa_modulus," ..
                                            " debian_weak_key, sign_algorithm, trusted_root, crl_url, ocsp_url," ..
                                            " subject_key_info, subject_key_info_sha256, subject_key_info_sha512)" ..
                                        " SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM certificates WHERE digest_sha512 = ?)";

        local spki = cert:spki();
        local _, pubkey_type, pubkey_bitsize = cert:pubkey();

        cert_id, err = execute_and_get_id(dbh, q, pem, date(cert:notbefore()):fmt("%Y-%m-%d %T"), date(cert:notafter()):fmt("%Y-%m-%d %T"), cert:digest("sha1"), cert:digest("sha256"),
                           cert:digest("sha512"), pubkey_bitsize, pubkey_type, cert:modulus(),
                           debian_weak_key(cert), cert:signature_alg(), false, cert:crl(), cert:ocsp(),
                           hex(spki), hex(sha256(spki)), hex(sha512(spki)), cert:digest("sha512"));

        -- A race condition, great. Lets retry the lookup.
        if err then
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

    stm = assert(dbh:prepare("SELECT COUNT(*) FROM certificate_sans WHERE certificate_id = ?"));

    assert(stm:execute(cert_id));

    local count = stm:fetch()[1];

    if cert:extensions()["2.5.29.17"] and count == 0 then
        local sans = cert:extensions()["2.5.29.17"];
        local dnsnames = {};
        local xmppaddrs = {};
        local srvnames = {};

        stm = assert(dbh:prepare("INSERT INTO certificate_sans (certificate_id, san_type, san_value) VALUES (?, ?, ?)"));

        if sans.dNSName then
            for k,v in ipairs(sans.dNSName) do
                assert(stm:execute(cert_id, "DNSName", v));
            end
        end

        if sans["1.3.6.1.5.5.7.8.5"] then
            for k,v in ipairs(sans["1.3.6.1.5.5.7.8.5"]) do -- xmppAddr
                assert(stm:execute(cert_id, "XMPPAddr", v));
            end
        end

        if sans["1.3.6.1.5.5.7.8.7"] then
            for k,v in ipairs(sans["1.3.6.1.5.5.7.8.7"]) do --= SRVName
                assert(stm:execute(cert_id, "SRVName", v));
            end
        end
    end

    local srv_certificate_id = assert(execute_and_get_id(dbh, "INSERT INTO srv_certificates (srv_result_id, certificate_id, chain_index) VALUES (?, ?, ?)", srv_result_id, cert_id, chain_index));

    print(srv_certificate_id);

    local stm = assert(dbh:prepare("INSERT INTO srv_certificate_errors (srv_certificates_id, message) VALUES (?, ?)"));

    for k,v in pairs(errors) do
        assert(stm:execute(srv_certificate_id, v));
    end


    dbh:commit();

    return cert_id;
end

return {
    insert_cert = insert_cert,
    execute_and_get_id = execute_and_get_id
}