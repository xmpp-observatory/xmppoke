-- Configuration handling

local short_opts = { v = "verbose", h = "html", o = "output", m = "mode", d = "delay" }
local opts = {
    mode = "client",
    html = false,
    output = "reports",
    verbose = false,
    delay = "2",
    capath = "/etc/ssl/certs",
    cafile = nil,
    key = nil,
    certificate = nil,
    blacklist = "/usr/share/openssl-blacklist/",
    version_jid = "poke@xnyhps.nl",
    version_password = nil,
    db_password = nil
    };

for _, opt in ipairs(arg) do
    if opt:match("^%-") then
        local name = opt:match("^%-%-?([^%s=]+)()")
        name = (short_opts[name] or name):gsub("%-+", "_");
        opts[name] = opt:match("=(.*)$") or true;
    else
        host = opt;
    end
end

local use_html = opts.html;
local sleep_for = tonumber(opts.delay);
local mode = opts.mode;
local cafile = opts.cafile;
local capath = opts.capath;
local key = opts.key;
local certificate = opts.certificate;
local openssl_blacklists = opts.blacklist;
local version_jid = opts.version_jid;
local version_password = opts.version_password;
local db_password = opts.db_password;

if not host or (mode ~= "server" and mode ~= "client") then
    print(string.format("Usage: %s [-v] [-h] [--out=reports/] [--mode=(server|client)] [--delay=seconds] [--capath=path] [--cafile=file] [--key=privatekey] [--certificate=certificate] [--blacklist=path] hostname", arg[0]));
    os.exit();
end

local jid = host;

-- Imports

local date = require("3rdparty/date");
local ssl = require("ssl");
local io = require("io");
local os = require("os");
local ciphertable = require("ciphertable");
local adns = require("net.adns");
local outputmanager = require("output")(use_html and "html" or "ansi");
local certmanager = require("certs")(openssl_blacklists);
local onions = require "onions";

local dbi = nil;

pcall(function () dbi = require('DBI') end);

local cert_verify_identity = require "util.x509".verify_identity;
local cert_load = require "ssl".x509.load;
local b64 = require "util.encodings".base64.encode
local verse = require("verse");
local to_ascii = require "util.encodings".idna.to_ascii;
local sha512 = require("util.hashes").sha512;
local sha256 = require("util.hashes").sha256;

local driver_name = nil;

outputmanager.init(opts.output, mode, host);

local dbh;

if dbi and driver_name == "SQLite3" then
    dbh = assert(dbi.Connect(driver_name, "results.db", nil, nil, nil, nil));

    last_insert_rowid = assert(dbh:prepare("SELECT last_insert_rowid() AS li"));

elseif dbi and driver_name == "PostgreSQL" then
    dbh = assert(dbi.Connect(driver_name, "xmppoke", "xmppoke", db_password, "localhost", 5432));

    local stm = assert(dbh:prepare("SET TIMEZONE = 'UTC';"));

    assert(stm:execute());
else
    local noop = function () end
    dbh = { execute = function () return {}; end
          , autocommit = noop
          , commit = noop
          , close = noop
          , prepare = function () return { execute = function () return {}; end, fetch = function () return nil; end }; end
          }
end

dbh:autocommit(false);

local function execute_and_get_id(q, ...)
    if driver_name == "PostgreSQL" then
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
    elseif driver_name == "SQLite3" then
        local stm = assert(dbh:prepare(q));

        local _, err = stm:execute(...);

        if err then return nil, err end

        err = last_insert_rowid:execute();

        if err then return nil, err end

        dbh:commit();

        return last_insert_rowid:fetch()[1];
    else
        return {}
    end
end

local result_id = execute_and_get_id("INSERT INTO test_results (server_name, test_date, type) VALUES (?, 'now', ?)", host, mode)

if opts.verbose then
    verse.set_log_handler(function(part, level, str) io.stdout:write(part .. "  " .. level .. "\t\t" .. str .. "\n") end);
end

local total_score = 0;
local public_key_score = 0;

local fail_untrusted = false;
local fail_ssl2 = false;
local fail_1024 = false;
local fail_md5 = false;
local cap_2048 = false;
local warn_rc4_tls11 = false;

local function deep_equal(a, b)
    if type(a) ~= type(b) then
        return false;
    end
    if type(a) == "table" then
        for k,_ in pairs(a) do
            if not deep_equal(a[k], b[k]) then
                return false;
            end
        end
        for k,_ in pairs(b) do
            if not deep_equal(a[k], b[k]) then
                return false;
            end
        end
        return true;
    end
    return a == b;
end

local function deep_copy(orig)
    local orig_type = type(orig);
    local copy;
    if orig_type == 'table' then
        copy = {};
        for orig_key, orig_value in next, orig, nil do
            copy[deep_copy(orig_key)] = deep_copy(orig_value);
        end
        setmetatable(copy, deep_copy(getmetatable(orig)));
    else
        copy = orig;
    end
    return copy;
end

local function keysize_score(pem, keytype, bits)
    if keytype == "RSA" or keytype == "DSA" then
        if bits == 0 then return 0; end
        if bits < 512 then return 20; end
        if bits < 1024 then return 40; end
        if bits < 2048 then return 80; end
        if bits < 4096 then return 90; end
        return 100;
    elseif keytype == "EC" then
        return 100;
    end
    -- Don't know how to judge DH...
    assert(false);
end

default_params = { mode = "client",
                  verify = {"peer","fail_if_no_peer_cert"},
                  verifyext = {"lsec_continue", "crl_check_chain"},
                  cafile = cafile,
                  capath = capath,
                  key = key,
                  certificate = certificate,
                  };

local function insert_cert(dbh, cert, srv_result_id, chain_index, errors)
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

        cert_id, err = execute_and_get_id(q, pem, date(cert:notbefore()):fmt("%Y-%m-%d %T"), date(cert:notafter()):fmt("%Y-%m-%d %T"), cert:digest("sha1"), cert:digest("sha256"),
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

    assert(stm:execute());

    local count = stm:fetch()[1];

    if cert:extensions()["2.5.29.17"] and count == 0 then
        local sans = cert:extensions()["2.5.29.17"];
        local dnsnames = {};
        local xmppaddrs = {};
        local srvnames = {};

        stm = assert(dbh:prepare("INSERT INTO certificate_sans (certificate_id, san_type, san_value) VALUES (?, ?, ?)"));

        for k,v in ipairs(sans.dNSName) do
            assert(stm:execute(cert_id, "DNSName", v));
        end

        for k,v in ipairs(sans["1.3.6.1.5.5.7.8.5"]) do -- xmppAddr
            assert(stm:execute(cert_id, "XMPPAddr", v));
        end

        for k,v in ipairs(sans["1.3.6.1.5.5.7.8.7"]) do --= SRVName
            assert(stm:execute(cert_id, "SRVName", v));
        end
    end

    local srv_certificate_id = assert(execute_and_get_id("INSERT INTO srv_certificates (srv_result_id, certificate_id, chain_index) VALUES (?, ?, ?)", srv_result_id, cert_id, chain_index));

    print(srv_certificate_id);

    local stm = assert(dbh:prepare("INSERT INTO srv_certificate_errors (srv_certificates_id, message) VALUES (?, ?)"));

    for k,v in pairs(errors) do
        assert(stm:execute(srv_certificate_id, v));
    end


    dbh:commit();

    return cert_id;
end

local sasl_done = false;
local sasl_tls_done = false;

function got_sasl(srv_result_id, features_stanza, tls)
    if (tls and not sasl_tls_done) or (not tls and not sasl_done) then

        local stanza = features_stanza:get_child("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");

        if not tls then
            outputmanager.print("Pre-TLS SASL mechanisms:");
        else
            outputmanager.print("Post-TLS SASL mechanisms:");
        end

        if not stanza then
            outputmanager.print("None");
        else
            for k,v in ipairs(stanza) do
                if v.name == "mechanism" then
                    outputmanager.print(v:get_text())

                    local sth = assert(dbh:prepare("INSERT INTO srv_mechanisms (srv_result_id, mechanism, after_tls) VALUES (?, ?, ?)"));
                    assert(sth:execute(srv_result_id, v:get_text(), tls));

                    dbh:commit();
                end
            end
        end

        outputmanager.line();

        if tls then
            sasl_tls_done = true;
        else
            sasl_done = true;
        end
    end
end

local cert_done = false;

function got_cert(c, tlsa_answer, srv_result_id)
    if not cert_done then
        local conn = c.conn:socket();

        if not conn.getpeercertificate then
            return;
        end

        outputmanager.line();

        local cert = conn:getpeercertificate();
        local chain_valid, errors = conn:getpeerverification();

        if tlsa_answer then

            outputmanager.print("TLSA verification results:");

            local matches = { [0] = function (c) return hex(c:der()) end, function (c) return c:digest("sha256") end, function (c) return c:digest("sha512") end }
            local matches_spki = { [0] = hex, function (c) return hex(sha256(c)) end, function (c) return hex(sha512(c)) end }

            for k,v in ipairs(tlsa_answer) do
                v.tlsa.found = false;
                if v.tlsa.use == 1 or v.tlsa.use == 3 then
                    if v.tlsa.select == 0 then
                        if matches[v.tlsa.match] and (matches[v.tlsa.match](cert) == hex(v.tlsa.data)) then
                            v.tlsa.found = v.tlsa.use == 3 or chain_valid;
                        end
                    elseif v.tlsa.select == 1 then
                        if matches_spki[v.tlsa.match] and (matches_spki[v.tlsa.match](cert:spki()) == hex(v.tlsa.data)) then
                            v.tlsa.found = v.tlsa.use == 3 or chain_valid;
                        end
                    end
                elseif v.tlsa.use == 0 or v.tlsa.use == 2 then
                    local i = 2;

                    while true do
                        local cert = conn:getpeercertificate(i);

                        if not cert then break end;

                        if v.tlsa.select == 0 then
                            if matches[v.tlsa.match] and (matches[v.tlsa.match](cert) == hex(v.tlsa.data)) then
                                v.tlsa.found = v.tlsa.use == 2 or chain_valid;
                            end
                        elseif v.tlsa.select == 1 then
                            if matches_spki[v.tlsa.match] and (matches_spki[v.tlsa.match](cert) == hex(v.tlsa.data)) then
                                v.tlsa.found = v.tlsa.use == 2 or chain_valid;
                            end
                        end

                        i = i + 1;
                    end
                end
            end

            local stm = assert(dbh:prepare("INSERT INTO tlsa_records (srv_result_id, usage, selector, match, data, verified) VALUES (?, ?, ?, ?, ?, ?)"));

            for k,v in ipairs(tlsa_answer) do
                outputmanager.print_no_nl((v.tlsa.found and (outputmanager.green .. "Success") or (outputmanager.red .. "Fail")) .. outputmanager.reset .. ": ");
                outputmanager.print_no_nl(v.tlsa:getUsage() .. " " .. v.tlsa:getSelector() .. " " .. v.tlsa:getMatchType() .. " (");
                outputmanager.print(((v.tlsa.match == 1 or v.tlsa.match == 2) and certmanager.pretty_fingerprint(hex(v.tlsa.data)) or (hex(v.tlsa.data:sub(1, 64)) .. "...")) .. ").");

                assert(stm:execute(srv_result_id, v.tlsa.use, v.tlsa.select, v.tlsa.match, hex(v.tlsa.data), v.tlsa.found == true));
            end

            dbh:commit();

            outputmanager.line();
        end

        outputmanager.print("Certificate details:");
        
        local chain_valid, errors = conn:getpeerverification();
        local valid_identity = cert_verify_identity(host, "xmpp-"..mode, cert);
        outputmanager.print("Valid for "..host..": "..(valid_identity and "Yes" or outputmanager.boldred .. "No" .. outputmanager.reset));

        if chain_valid then
            outputmanager.print("Trusted certificate: Yes");
        else
            outputmanager.print("Trusted certificate: " .. outputmanager.red .. "No" .. outputmanager.reset);
            certmanager.print_errors(outputmanager.print, errors);
            fail_untrusted = true;
        end

        if not valid_identity then
            fail_untrusted = true;
        end

        if cert:bits() < 1024 then
            fail_1024 = true;
        elseif cert:bits() < 2048 then
            cap_2048 = true;
        end

        if cert:signature_alg() == "md5WithRSAEncryption" then
            fail_md5 = true;
        end

        outputmanager.line();
        outputmanager.print("Certificate chain:");

        local certs = conn:getpeerchain();
        local current_cert = cert;
        local used_certs = {};
        local chain = {};

        local i = 1;

        while true do

            used_certs[i] = true;

            outputmanager.line();

            outputmanager.print(i-1 .. ":");

            pretty_cert(outputmanager, current_cert);
            local cert_id = insert_cert(dbh, current_cert, srv_result_id, i - 1, errors and errors[i] or {});

            chain[#chain + 1] = cert_id;

            if #chain > 1 then
                local stm = assert(dbh:prepare("UPDATE certificates SET signed_by_id = ? WHERE certificate_id = ?"));

                assert(stm:execute(cert_id, chain[#chain - 1]));

                dbh:commit();
            end

            local new_cert = nil;
            i = nil;

            for k,v in ipairs(certs) do
                local res, err = conn:did_issue(v, current_cert);
                if res > 0 then
                    new_cert = v;
                    i = k;
                    break;
                end
            end

            if new_cert == nil then

                -- Try to find it in the database before we give up.

                local q = {};
                local args = {}

                for k,v in pairs(current_cert:issuer()) do
                    q[#q + 1] = "SELECT certificate_id FROM certificate_subjects WHERE (name = ? AND value = ?)"
                    args[#args + 1] = v.name;
                    args[#args + 1] = v.value;
                end

                -- We know nothing. Too much to search through, we give up.
                if #q == 0 then
                    break;
                end
                
                local query = table.concat(q, " INTERSECT ");

                local stm = assert(dbh:prepare(query));

                assert(stm:execute(unpack(args)));

                local result = stm:fetch();

                if not result then
                    break
                end

                for k,v in pairs(result) do
                    local stm = assert(dbh:prepare("SELECT pem FROM certificates WHERE certificate_id = ?"));

                    assert(stm:execute(v));

                    local pem = stm:fetch()[1];

                    local candidate = cert_load(pem);

                    if conn:did_issue(candidate, current_cert) then
                        local stm = assert(dbh:prepare("UPDATE certificates SET signed_by_id = ? WHERE certificate_id = ?"));

                        assert(stm:execute(v, cert_id));

                        dbh:commit();
                    end
                end

                break
            end;

            if new_cert:pem() == current_cert:pem() then
                outputmanager.print("Self signed certificate.");

                local stm = assert(dbh:prepare("UPDATE certificates SET signed_by_id = ? WHERE certificate_id = ?"));

                assert(stm:execute(cert_id, cert_id));

                dbh:commit();

                break;
            end

            if used_certs[i] then
                outputmanager.print(outputmanager.red .. "Certificate chain contains a cycle." .. outputmanager.reset);
                break;
            end

            current_cert = new_cert;
        end

        outputmanager.line();

        for k,v in ipairs(certs) do
            if not used_certs[k] then
                outputmanager.print(outputmanager.red .. "Found unused certificate in chain:" .. outputmanager.reset);
                outputmanager.print(k-1 .. ":");

                pretty_cert(outputmanager, v);
                insert_cert(dbh, v, srv_result_id, k - 1, errors and errors[k] or {});

                outputmanager.line();
            end
        end

        -- Hack: if the subject is identical, we assume the server sent its root CA too.
        if deep_equal(current_cert:issuer(), current_cert:subject()) then
            outputmanager.print(outputmanager.red .. "Root CA certificate was included in chain." .. outputmanager.reset);
        else
            outputmanager.print("Root CA: ");
            certmanager.print_subject(outputmanager.print, current_cert:issuer());
        end

        local certificate_score = 0;

        if chain_valid and valid_identity then
            certificate_score = 100;
        end

        outputmanager.line();

        outputmanager.print(outputmanager.green .. "Certificate score: " .. certificate_score .. outputmanager.reset);

        local pubkey, keytype, bits = cert:pubkey();

        outputmanager.print(keytype .. " " .. bits);

        public_key_score = keysize_score(cert:pubkey());

        outputmanager.line();
        outputmanager.print("Compression: " .. (conn:info("compression") or "none"));
        
        local sth = assert(dbh:prepare("UPDATE srv_results SET compression = ?, certificate_score = ?, valid_identity = ?, trusted = ? WHERE srv_result_id = ?"));
        assert(sth:execute(conn:info("compression"), certificate_score, valid_identity, chain_valid, srv_result_id));

        dbh:commit();

        outputmanager.line();

        cert_done = true;
    end
end

local features_done = false;

function test_params(target, port, params, tlsa_answer, srv_result_id)
    local c = verse.new();
    local done = false;

    c.tlsparams = params;
    c.connect_host = target;
    c.connect_port = port;

    if target:find(".onion(.?)$") then
        c.connect = function (session, host, port)
            return onions.connect_socks5(session, host, port);
        end
    end

    c:hook("outgoing-raw", function (data) return c:debug("OUT: " .. data); end);
    c:hook("incoming-raw", function (data) return c:debug("IN: " .. data); end);

    c:hook("stream-error", function(event)
        if event:get_child("host-unknown", "urn:ietf:params:xml:ns:xmpp-streams") then
            local sth = assert(dbh:prepare("UPDATE srv_results SET error = ?, done = 't' WHERE srv_result_id = ? AND error IS NULL"));
            assert(sth:execute("This server does not serve " .. jid  .. ".", srv_result_id));
            dbh:commit();
            outputmanager.print(outputmanager.red .. "This server does not serve " .. jid  .. "." .. outputmanager.reset);
            if event.from then
                outputmanager.print(outputmanager.red .. "It appears to be for " .. event.from  .. " instead." .. outputmanager.reset);
            end
            c:close();
            return true;
        end
    end, 1000)

    c:hook("stream-features", function (features_stanza)
        local stanza = features_stanza:get_child("starttls", "urn:ietf:params:xml:ns:xmpp-tls");

        c:debug("Features!");

        got_sasl(srv_result_id, features_stanza, done);

        if done then
            c:debug("Closing stream");
            
            local info = c.conn:socket():info();

            c.conn:socket():close();
            
            verse.add_task(sleep_for, function ()
                assert(coroutine.resume(co, info));
            end);

            return false;
        end

        if stanza and stanza:get_child("required") then
            if not features_done then
                outputmanager.print("Server " .. outputmanager.green .. "requires" .. outputmanager.reset .. " starttls.");
                features_done = true;

                local sth = assert(dbh:prepare("UPDATE srv_results SET requires_starttls = ? WHERE srv_result_id = ?"));
                assert(sth:execute(true, srv_result_id));

                dbh:commit();
            end
        elseif stanza then
            if not features_done then
                outputmanager.print("Server " .. outputmanager.red .. "allows" .. outputmanager.reset .. " starttls.");
                features_done = true;

                local sth = assert(dbh:prepare("UPDATE srv_results SET requires_starttls = ? WHERE srv_result_id = ?"));
                assert(sth:execute(false, srv_result_id));

                dbh:commit();
            end
        else
            if not features_done then
                outputmanager.print(outputmanager.boldred .. "Server does not offer starttls!" .. outputmanager.reset);
                local sth = assert(dbh:prepare("UPDATE srv_results SET error = ?, done = 't' WHERE srv_result_id = ? AND error IS NULL"));
                assert(sth:execute("Server does not support encryption.", srv_result_id));
                dbh:commit();

                features_done = true;
            end
            
            done = true;

            verse.add_task(sleep_for, function ()
                assert(coroutine.resume(co, nil, "No starttls offered"));
            end);
        end
    end, 1000);

    c:hook("status", function (status)
        if status == "ssl-handshake-complete" and not done then

            got_cert(c, tlsa_answer, srv_result_id);

            done = true;
        end
    end, 1000);

    c:hook("disconnected", function ()
        if not done then
            done = true;
            verse.add_task(sleep_for, function ()
                assert(coroutine.resume(co, nil, "Disconnected"));
            end);
        end
    end);

    verse.add_task(30, function ()
        if not done then
            c:debug("Handshake took 30 seconds. Giving up.");
            done = true;
            verse.add_task(sleep_for, function ()
                assert(coroutine.resume(co, nil, "Timeout"));
            end);
        end
    end);

    c:connect_client(jid);
end

local function color_bits(bits)
    if bits < 128 then
        return outputmanager.boldred .. bits .. outputmanager.reset;
    elseif bits < 256 then
        return outputmanager.green .. bits .. outputmanager.reset;
    else
        return outputmanager.boldgreen .. bits .. outputmanager.reset;
    end
end

local function pretty_cipher(info)
    local judgement = ""

    if info.bits < 128 then
        judgement = outputmanager.boldred .. " WEAK!" .. outputmanager.reset
    end

    if info.cipher:find("ECDHE-") == 1 or info.cipher:find("DHE-") == 1 then
        judgement = judgement .. outputmanager.boldblue .. " FS" .. outputmanager.reset
    end

    return info.cipher .. " (" .. color_bits(info.bits) .. ") " .. string.format("0x%02X", ciphertable.find(info.cipher)) .. judgement;
end

local function print_cipher_result(info, err)
    if err then
        outputmanager.print(outputmanager.red .. "Fail: " .. err .. outputmanager.reset);
    else
        outputmanager.print("OK: " .. pretty_cipher(info));
    end
end

local function print_result(bad, info, err)
    if err then
        if bad then outputmanager.print_no_nl(outputmanager.green); end
        if not bad then outputmanager.print_no_nl(outputmanager.red); end
        outputmanager.print("No." .. outputmanager.reset);
        return false;
    else
        if bad == true then outputmanager.print_no_nl(outputmanager.red); end
        if bad == false then outputmanager.print_no_nl(outputmanager.green); end
        outputmanager.print("Yes." .. outputmanager.reset);
        return true;
    end
end

local function test_server(target, port, co, tlsa_answer, srv_result_id)
    total_score = 0;
    public_key_score = 0;
    fail_untrusted = false;
    fail_ssl2 = false;

    local params;

    -- if mode == "client" then
    --     test_sasl(target, port, srv_result_id);

    --     coroutine.yield();
    -- end

    local protocols = {};
    local lowest_protocol, highest_protocol;

    outputmanager.print("Testing protocol support:");
    outputmanager.print_no_nl("Testing SSLv2 support... ");
    params = default_params;
    params.options = {"no_sslv3"};
    params.protocol = "sslv2";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    if print_result(true, coroutine.yield()) then
        protocols[#protocols + 1] = "sslv2";
        lowest_protocol = 20;
        highest_protocol = 20;
        fail_ssl2 = true;
    end
    
    outputmanager.print_no_nl("Testing SSLv3 support... ");
    
    params = deep_copy(default_params);
    params.options = {"no_sslv2"};
    params.protocol = "sslv3";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    if print_result(nil, coroutine.yield()) then
        protocols[#protocols + 1] = "sslv3";
        if not lowest_protocol then lowest_protocol = 80; end
        highest_protocol = 80;
    end

    outputmanager.print_no_nl("Testing TLSv1 support... ");

    params = deep_copy(default_params);
    params.options = {"no_sslv3"};
    params.protocol = "tlsv1";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    if print_result(nil, coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1";
        if not lowest_protocol then lowest_protocol = 90; end
        highest_protocol = 90;
    end
    
    outputmanager.print_no_nl("Testing TLSv1.1 support... ");

    params = deep_copy(default_params);
    params.options = {"no_sslv3","no_tlsv1"};
    params.protocol = "tlsv1_1";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    if print_result(false, coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1_1";
        if not lowest_protocol then lowest_protocol = 95; end
        highest_protocol = 95;
    end

    outputmanager.print_no_nl("Testing TLSv1.2 support... ");

    params = deep_copy(default_params);
    params.options = {"no_sslv3","no_tlsv1","no_tlsv1_1"};
    params.protocol = "tlsv1_2";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    if print_result(false, coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1_2";
        if not lowest_protocol then lowest_protocol = 100; end
        highest_protocol = 100;
    end

    local sth = assert(dbh:prepare("UPDATE srv_results SET sslv2 = '0', sslv3 = '0', tlsv1 = '0', tlsv1_1 = '0', tlsv1_2 = '0' WHERE srv_result_id = ?;"));
    assert(sth:execute(srv_result_id));

    if mode == "server" and #protocols > 0 then
        params = deep_copy(default_params);
        params.key = nil;
        params.certificate = nil;
        params.protocol = protocols[1];

        test_params(target, port, params, tlsa_answer, srv_result_id);

        local info, err = coroutine.yield();

        if not info then
            outputmanager.print("Server " .. outputmanager.green .. "requires" .. outputmanager.reset .. " initiating server to present a certificate.");

            local sth = assert(dbh:prepare("UPDATE srv_results SET requires_peer_cert = '1' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();
        else
            outputmanager.print("Server does not require the initiating server to present a certificate.");
        end

        outputmanager.line();
    end

    for k,v in ipairs(protocols) do
        -- v can only be sslv2, sslv3, tlsv1, tlsv1_1 or tlsv1_2, so this is fine. Really.
        local sth = assert(dbh:prepare("UPDATE srv_results SET " .. v .. " = '1' WHERE srv_result_id = ?"));
        assert(sth:execute(srv_result_id));
    end

    dbh:commit();

    if #protocols == 0 then
        outputmanager.print(outputmanager.red .. "No SSL or TLS support detected." .. outputmanager.reset);

        local sth = assert(dbh:prepare("UPDATE srv_results SET error = ?, done = 't' WHERE srv_result_id = ? AND error IS NULL"));
        assert(sth:execute("Connection failed.", srv_result_id));
        dbh:commit();

        return
    end

    local protocol_score = (lowest_protocol + highest_protocol)/2;

    outputmanager.print(outputmanager.green .. "Protocol score: " .. protocol_score .. outputmanager.reset);

    local sth = assert(dbh:prepare("UPDATE srv_results SET protocol_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(protocol_score, srv_result_id));

    dbh:commit();

    total_score = total_score + 0.3 * protocol_score;

    outputmanager.line();
    outputmanager.print("Determining cipher support:");

    local cipher_string = "ALL:COMPLEMENTOFALL";
    local ciphers = {};
    local cipher_key_score_override = nil;

    for i=#protocols,1,-1 do
        local v = protocols[i];
        while true do
            local params = deep_copy(default_params);
            params.protocol = v;
            params.ciphers = cipher_string;
            test_params(target, port, params);

            local info, err = coroutine.yield();

            if not info then break end;

            ciphers[#ciphers + 1] = info;

            print(cipher_string, info.cipher);

            cipher_string = cipher_string .. ":!" .. info.cipher;

            if info.export and not cipher_key_score_override then
                outputmanager.print(outputmanager.red .. "Server supports EXPORT cipher, key exchange score capped to 40." .. outputmanager.reset);
                cipher_key_score_override = 40;
            end

            if info.authentication == "None" then
                outputmanager.print(outputmanager.red .. "Server supports ADH cipher, key exchange score capped to 0." .. outputmanager.reset);
                cipher_key_score_override = 0;
            end

            if info.encryption == "RC4(128)" and (v == "tslv1_1" or v == "tlsv1_2") then
                warn_rc4_tls11 = true;
            end
       end
    end

    if cipher_key_score_override and cipher_key_score_override < public_key_score then
        public_key_score = cipher_key_score_override;
    end

    local sth = assert(dbh:prepare("UPDATE srv_results SET keysize_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(public_key_score, srv_result_id));

    dbh:commit();
    
    outputmanager.print(outputmanager.green .. "Key exchange score: " .. public_key_score .. outputmanager.reset);

    total_score = total_score + 0.3 * public_key_score;

    local should_sort = true;

    if #ciphers > 1 then
        local cipher1 = ciphers[1];
        local cipher2 = ciphers[2];
        local protocol = protocols[#protocols];

        local params = deep_copy(default_params);
        params.protocol = protocol;
        params.ciphers = cipher1.cipher .. ":" .. cipher2.cipher;
        test_params(target, port, params);
        local result1, err1 = coroutine.yield();

        local params = deep_copy(default_params);
        params.protocol = protocol;
        params.ciphers = cipher2.cipher .. ":" .. cipher1.cipher;
        test_params(target, port, params);
        local result2, err2 = coroutine.yield();

        if not result1 or not result2 then
            outputmanager.print(outputmanager.red .. "Problem with testing server's ordering. " .. tostring(err1) .. " " .. tostring(err2) .. outputmanager.reset);
        elseif result1.cipher == result2.cipher then
            outputmanager.print("Server does " .. outputmanager.red .. "not" .. outputmanager.reset .. " respect client's cipher ordering. Server's order:");
            should_sort = false;

            local sth = assert(dbh:prepare("UPDATE srv_results SET reorders_ciphers = '1' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();
        else
            local sth = assert(dbh:prepare("UPDATE srv_results SET reorders_ciphers = '0' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();

            outputmanager.print("Server does respect client's cipher ordering.");
        end
    end

    if should_sort then
        table.sort(ciphers, function (a, b)
            if a.bits == b.bits then
                if a.protocol == b.protocol then
                    return a.cipher < b.cipher;
                else
                    return a.protocol > b.protocol;
                end
            else
                return a.bits > b.bits;
            end
        end);
    end

    local max_bits = 0;
    local min_bits = math.huge;

    local sth = assert(dbh:prepare("INSERT INTO srv_ciphers (srv_result_id, cipher_id, cipher_index) VALUES (?, ?, ?)"));

    for k,v in ipairs(ciphers) do
        assert(sth:execute(srv_result_id, ciphertable.find(v.cipher), k - 1));

        outputmanager.print(pretty_cipher(v));
        if v.bits < min_bits then min_bits = v.bits; end;
        if v.bits > max_bits then max_bits = v.bits; end;
    end

    dbh:commit();

    local function cipher_score(bits)
        if bits == 0 then return 0 end
        if bits < 128 then return 20 end
        if bits < 256 then return 80 end
        return 100
    end

    local cipher_score = (cipher_score(max_bits) + cipher_score(min_bits))/2;

    outputmanager.print(outputmanager.green .. "Cipher score: " .. cipher_score .. outputmanager.reset);

    total_score = total_score + 0.4 * cipher_score;
    
    local sth = assert(dbh:prepare("UPDATE srv_results SET cipher_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(cipher_score, srv_result_id));

    dbh:commit();

    if mode == "client" then

        outputmanager.line();
        outputmanager.print("Estimating client cipher support:");

        local clients = {
            { name = "Adium 1.5.7 on OS X 10.8"
            , ciphers = "AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:EXP-RC4-MD5:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA" };
            { name = "Adium 1.5.8hg on OS X 10.8"
            , ciphers = "ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA" };
            { name = "Pidgin 2.10.7 on Windows 8"
            , ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:DSS-RC4-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:SSL_RSA_FIPS_WITH_DES_CBC_SHA:DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC2-CBC-MD5" };
            { name = "Gajim 0.15.4 on Windows 8"
            , ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5" };
            { name = "Jitsi 2.2.4603.9615 on Windows 8"
            , ciphers = "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5" };
            { name = "Jitsi 2.2.4603.9615 on OS X 10.8"
            , ciphers = "RC4-MD5:RC4-MD5:RC4-SHA:AES128-SHA:AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DES-CBC3-SHA:DES-CBC3-MD5:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC-SHA:DES-CBC-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA" };
            { name = "Psi 0.15 on OS X 10.8"
            , ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:RC2-CBC-MD5:RC4-SHA:RC4-MD5:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5" };
            { name = "Messages 7.0.1 (3322) on OS X 10.8"
            , ciphers = "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA" };
            { name = "Pidgin 2.10.6 on Debian 7.1"
            , ciphers = "DHE-DSS-AES256-SHA:AES256-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA" };
            { name = "Empathy 3.4.2.3 on Debian 7.1"
            , ciphers = "DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:AES128-SHA:AES128-SHA256:CAMELLIA128-SHA:AES256-SHA:AES256-SHA256:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5" };
            { name = "Swift 2.0beta1-dev47 on Debian 7.1"
            , ciphers = "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5" };
            { name = "Psi 0.14 on Debian 7.1"
            , ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5" };
            { name = "irssi-xmpp 0.52 on Debian 7.1"
            , ciphers = "DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:AES128-SHA:AES128-SHA256:CAMELLIA128-SHA:AES256-SHA:AES256-SHA256:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5" };
            { name = "Trillian 1.4.52 on OS X 10.8"
            , ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:SEED-SHA:RC2-CBC-MD5:RC4-SHA:RC4-MD5:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5" };
            { name = "GibberBot 0.0.11RC5/yaxim 0.8.6b/Xabber 0.2.29a/Beem 0.1.8 on Android 4.3"
            , ciphers = "RC4-MD5:RC4-SHA:AES128-SHA:AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA" };
            { name = "ChatSecure on iOS 6.1"
            , ciphers = "ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES256-SHA384:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES256-SHA384:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES256-SHA256:AES128-SHA256:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-RSA-NULL-SHA:ECDH-ECDSA-NULL-SHA:ECDH-RSA-NULL-SHA:NULL-SHA256:NULL-SHA:NULL-MD5" };
            { name = "Cryptocat 2.1.12 Firefox 23.0.1 extension on OS X 10.8"
            , ciphers = "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:CAMELLIA256-SHA:AES256-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-AES128-SHA:SEED-SHA:CAMELLIA128-SHA:AES128-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA" };
            { name = "Cryptocat 2.1.12 on OS X 10.8"
            , ciphers = "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA" };
            { name = "MCabber 0.10.1 on Gentoo"
            , ciphers = "DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:DHE-DSS-RC4-SHA:AES128-SHA:AES128-SHA256:CAMELLIA128-SHA:AES256-SHA:AES256-SHA256:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5" };
            { name = "Psi 0.15 on Windows 7"
            , ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5" };
            { name = "poezio 0.7.5.2 with Python 3.3 on OS X 10.8/poezio git HEAD on Arch"
            , ciphers = "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5" };
            { name = "Kopete 1.4.5 with KDE 4.10.5"
            , ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5" };
            { name = "Miranda NG v0.94.4 #5216 x64, jabber.dll 0.11.0.2 on Windows 7 Pro SP1 x64"
            , ciphers = "AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5" };
        };

        for _,client in ipairs(clients) do
            outputmanager.print_no_nl(client.name .. ":");

            for i=0,75-#client.name do
                outputmanager.print_no_nl(" ");
            end

            local client_ciphers = {};

            for c in client.ciphers:gmatch("([^:]+)") do
                client_ciphers[#client_ciphers + 1] = { cipher = c };
            end

            local function find_common(a, b)
                for k,v in ipairs(a) do
                    for k2,v2 in ipairs(b) do
                        if v.cipher == v2.cipher then
                            return v, v2
                        end
                    end
                end
                return nil, nil
            end

            local c = nil;
            
            if should_sort then
                _, c = find_common(client_ciphers, ciphers);
            else
                c, _ = find_common(ciphers, client_ciphers);
            end

            if c == nil then
                outputmanager.print(outputmanager.red .. "No common ciphers!" .. outputmanager.reset);
            else
                outputmanager.print(pretty_cipher(c));
            end
        end
    end

    local function grade(score)
        if score >= 80 then return "A"; end
        if score >= 65 then return "B"; end
        if score >= 50 then return "C"; end
        if score >= 35 then return "D"; end
        if score >= 20 then return "E"; end
        return "F";
    end

    outputmanager.line();
    outputmanager.print(outputmanager.green .. "Total score: " .. total_score);

    if fail_untrusted then
        outputmanager.print(outputmanager.red .. "Grade: F (Untrusted certificate)" .. outputmanager.reset);
        outputmanager.print(outputmanager.green .. "When ignoring trust: ");
    end
    
    local final_grade = grade(total_score);

    if fail_ssl2 then
        outputmanager.print(outputmanager.red .. "Grade set to F due to support for obsolete and insecure SSLv2." .. outputmanager.reset);
        final_grade = "F";
    end
    
    if fail_1024 then
        outputmanager.print(outputmanager.red .. "Grade set to F due to <1024 bit RSA key." .. outputmanager.reset);
        final_grade = "F";
    end
    
    if fail_md5 then
        outputmanager.print(outputmanager.red .. "Grade set to F due to using a MD5 based signature." .. outputmanager.reset);
        final_grade = "F";
    end

    if cap_2048 then
        outputmanager.print(outputmanager.red .. "Grade capped to B due to <2048 bit RSA key." .. outputmanager.reset);
        if final_grade == "A" then
            final_grade = "B";
        end
    end

    if not (highest_protocol == 100) then
        outputmanager.print(outputmanager.red .. "Grade capped to B due to missing support for TLS 1.2." .. outputmanager.reset);
        if final_grade == "A" then
            final_grade = "B";
        end
    end

    if warn_rc4_tls11 then
        outputmanager.print(outputmanager.red .. "Warning: Server allows RC4 with TLS 1.1 and/or 1.2." .. outputmanager.reset);
    end

    outputmanager.print("Grade: " .. final_grade  .. outputmanager.reset);

    local sth = assert(dbh:prepare("UPDATE srv_results SET total_score = ?, grade = ?, done = '1', warn_rc4_tls11 = ? WHERE srv_result_id = ?"));
    assert(sth:execute(total_score, final_grade, warn_rc4_tls11, srv_result_id));

    dbh:commit();

    return nil;
end

co = coroutine.create(function ()
        local f = adns.lookup(function (a) assert(coroutine.resume(co, a)) end, "_xmpp-" .. mode .. "._tcp." .. to_ascii(host), "SRV");
        local srv_records = coroutine.yield();

        if version_jid and version_password then
            outputmanager.print_no_nl("Determining server version: ");

            local version = require("verse").init("client").new();

            version:add_plugin("version");

            version:connect_client(version_jid, version_password);

            local done = false;

            version:hook("ready", function ()
                version:query_version(host, function (v)
                        if not done then
                            assert(coroutine.resume(co, (v.name or "unknown") .. " " .. (v.version or "unknown")));
                            version:close();
                            done = true;
                        end
                end);
            end);

            verse.add_task(15, function ()
                if not done then
                    coroutine.resume(co);
                    version:close();
                    done = true;
                end
            end);

            local result = coroutine.yield();

            local stm = assert(dbh:prepare("UPDATE test_results SET version = ? WHERE test_id = ?"));

            assert(stm:execute(result, result_id));

            outputmanager.print(result);

            package.loaded["verse.client"] = nil;
        end

        verse = require("verse").init(mode);

        outputmanager.print("DNS details:");

        if srv_records and srv_records.secure then
            outputmanager.print("SRV records verified using " .. outputmanager.green .. "DNSSEC" .. outputmanager.reset .. ".");
        elseif srv_records and srv_records.bogus then
            outputmanager.print("SRV records failed " .. outputmanager.red .. "DNSSEC" .. outputmanager.reset .. " validation.");
        end

        local stm = assert(dbh:prepare("UPDATE test_results SET srv_dnssec_good = ?, srv_dnssec_bogus = ? WHERE test_id = ?"));

        assert(stm:execute(srv_records and srv_records.secure, srv_records and srv_records.bogus, result_id));

        if srv_records and #srv_records > 0 then
            outputmanager.print("SRV records:");

            outputmanager.print(srv_records);

            outputmanager.line();
        else
            local port = (mode == "client" and 5222) or 5269;

            outputmanager.print(outputmanager.red .. "No SRV records found. Falling back to " .. host .. ":" .. port .. "." .. outputmanager.reset);
            srv_records = { { srv = { port = port, target = host } } };
        end

        local q = "INSERT INTO srv_results (test_id, priority, weight, port, target, cipher_score, certificate_score, keysize_score, protocol_score, total_score, requires_peer_cert, done, tlsa_dnssec_good, tlsa_dnssec_bogus) " ..
                                             "VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, 0.0, '0', '0', ?, ?)";
        
        for k,v in ipairs(srv_records) do
            local srv = v.srv;
            
            features_done = false;
            cert_done = false;
            sasl_done = false;
            sasl_tls_done = false;

            outputmanager.print("Testing server: " .. srv.target .. ":" .. srv.port .. ".");

            local tlsa = "_" .. srv.port .. "._tcp." .. srv.target;
            local tlsa_supported = (not require("net.dns").types) or (require("net.dns").types[52] == "TLSA");
            local tlsa_answer = nil;
            local srv_id;

            if tlsa_supported then

                outputmanager.print("TLSA records:");

                local f = adns.lookup(function (a) assert(coroutine.resume(co, a)) end, tlsa, "TLSA");

                tlsa_answer = coroutine.yield();

                if tlsa_answer.secure then
                    outputmanager.print(outputmanager.green .. "DNSSEC secured" .. outputmanager.reset .. " TLSA records for " .. tlsa .. ":\n" .. tostring(tlsa_answer));
                elseif tlsa_answer.bogus then
                    outputmanager.print(outputmanager.red .. "bogus" .. outputmanager.reset " TLSA records for " .. tlsa .. ":\n" .. tostring(tlsa_answer));
                end

                srv_id = assert(execute_and_get_id(q, result_id, srv.priority, srv.weight, srv.port, srv.target, tlsa_answer.secure, tlsa_answer.bogus));

                dbh:commit();
            else
                outputmanager.print("No luaunbound support detected. Skipping TLSA records.");
                srv_id = assert(execute_and_get_id(q, result_id, srv.priority, srv.weight, srv.port, srv.target, nil, nil));
            end

            test_server(srv.target, srv.port, co, tlsa_answer, srv_id);
            outputmanager.line();
        end

        outputmanager.finish();

        dbh:commit();

        dbh:close();

        os.exit();
end)

verse.add_task(0, function ()
    assert(coroutine.resume(co));
end);

verse.add_task(30 * 60, function ()
    outputmanager.print("Test is taking 30 minutes already. We're probably stuck.");
    os.exit();
end);

verse.loop();
