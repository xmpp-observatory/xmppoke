-- Configuration handling

local short_opts = { v = "verbose", m = "mode", d = "delay" }
local opts = {
    mode = "client",
    verbose = false,
    delay = "2",
    capath = "/etc/ssl/certs",
    cafile = nil,
    key = nil,
    certificate = nil,
    blacklist = "/usr/share/openssl-blacklist/",
    version_jid = "poke@xnyhps.nl",
    version_password = nil,
    db_password = nil,
    db_host = "localhost",
    db_port = 5432
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
local db_host = opts.db_host;
local db_port = opts.db_port;

if not host or (mode ~= "server" and mode ~= "client") then
    print(string.format("Usage: %s [-v] [--mode=(server|client)] [--delay=seconds] [--capath=path] [--cafile=file] [--key=privatekey] [--certificate=certificate] [--blacklist=path] hostname", arg[0]));
    os.exit();
end

local jid = host;

-- Imports

local date = require("3rdparty.date");
local ssl = require("ssl");
local io = require("io");
local os = require("os");
local ciphertable = require("ciphertable");
local adns = require("net.adns");
local sql = require("sql");
local certmanager = require("certs")(openssl_blacklists);
local onions = require "onions";

local dbi = require('DBI');

local cert_verify_identity = require "util.x509".verify_identity;
local cert_load = require "ssl".x509.load;
local b64 = require "util.encodings".base64.encode
local verse = require("verse");
local to_ascii = require "util.encodings".idna.to_ascii;
local sha512 = require("util.hashes").sha512;
local sha256 = require("util.hashes").sha256;

local log = require("util.logger").init("poke");


if opts.verbose then
    verse.set_log_handler(function(part, level, str) io.stdout:write(part .. "  " .. level .. "\t\t" .. str .. "\n") end);
end


log("debug", "Connecting to database on " .. db_host .. ":" .. db_port .. ".")

local dbh = assert(dbi.Connect("PostgreSQL", "xmppoke", "xmppoke", db_password, db_host, db_port));

local stm = assert(dbh:prepare("SET TIMEZONE = 'UTC';"));

assert(stm:execute());

dbh:autocommit(false);

local result_id = sql.execute_and_get_id(dbh, "INSERT INTO test_results (server_name, test_date, type) VALUES (?, 'now', ?)", host, mode)


local total_score = 0;
local public_key_score = 0;

local fail_untrusted = false;
local fail_ssl2 = false;
local fail_1024 = false;
local fail_md5 = false;

local cap_dh_2048 = false;
local cap_ssl3 = false;
local cap_2048 = false;
local cap_compression = false;

local warn_rc4_tls11 = false;
local warn_no_fs = true;

local sasl_done = false;
local sasl_tls_done = false;

local cert_done = false;

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

local default_params = { mode = "client",
                      verify = {"peer","fail_if_no_peer_cert"},
                      verifyext = {"lsec_continue", "crl_check_chain"},
                      cafile = cafile,
                      capath = capath,
                      key = key,
                      certificate = certificate,
                      };

function got_sasl(srv_result_id, features_stanza, tls)
    if (tls and not sasl_tls_done) or (not tls and not sasl_done) then

        local stanza = features_stanza:get_child("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");

        if stanza then
            for k,v in ipairs(stanza) do
                if v.name == "mechanism" then
                    
                    local sth = assert(dbh:prepare("INSERT INTO srv_mechanisms (srv_result_id, mechanism, after_tls) VALUES (?, ?, ?)"));
                    assert(sth:execute(srv_result_id, v:get_text(), tls));

                    dbh:commit();
                end
            end
        end

        if tls then
            sasl_tls_done = true;
        else
            sasl_done = true;
        end
    end
end

function got_cert(c, tlsa_answer, srv_result_id)
    if not cert_done then
        local conn = c.conn:socket();

        if not conn.getpeercertificate then
            return;
        end

        local cert = conn:getpeercertificate();
        local chain_valid, errors = conn:getpeerverification();

        if tlsa_answer then

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
                            if matches_spki[v.tlsa.match] and (matches_spki[v.tlsa.match](cert:spki()) == hex(v.tlsa.data)) then
                                v.tlsa.found = v.tlsa.use == 2 or chain_valid;
                            end
                        end

                        i = i + 1;
                    end
                end
            end

            local stm = assert(dbh:prepare("INSERT INTO tlsa_records (srv_result_id, usage, selector, match, data, verified) VALUES (?, ?, ?, ?, decode(?, 'hex'), ?)"));

            for k,v in ipairs(tlsa_answer) do
                assert(stm:execute(srv_result_id, v.tlsa.use, v.tlsa.select, v.tlsa.match, hex(v.tlsa.data), v.tlsa.found == true));
            end

            dbh:commit();
        end
                
        local chain_valid, errors = conn:getpeerverification();
        local valid_identity = cert_verify_identity(host, "xmpp-"..mode, cert);
        
        if not chain_valid then
            fail_untrusted = true;
        end

        if not valid_identity then
            fail_untrusted = true;
        end

        local _, keytype = cert:pubkey()

        if keytype == "RSA" or keytype == "DSA" then
            if cert:bits() < 1024 then
                fail_1024 = true;
            elseif cert:bits() < 2048 then
                cap_2048 = true;
            end
        end

        if cert:signature_alg() == "md5WithRSAEncryption" then
            fail_md5 = true;
        end

        local certs = conn:getpeerchain();
        local current_cert = cert;
        local used_certs = {};
        local chain = {};

        local i = 1;

        while true do

            used_certs[i] = true;

            local cert_id = sql.insert_cert(dbh, current_cert, srv_result_id, i - 1, errors and errors[i] or {});

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
                local stm = assert(dbh:prepare("UPDATE certificates SET signed_by_id = ? WHERE certificate_id = ?"));

                assert(stm:execute(cert_id, cert_id));

                dbh:commit();

                break;
            end

            if used_certs[i] then
                break;
            end

            current_cert = new_cert;
        end

        for k,v in ipairs(certs) do
            if not used_certs[k] then
                sql.insert_cert(dbh, v, srv_result_id, k - 1, errors and errors[k] or {});
            end
        end

        local certificate_score = 0;

        if chain_valid and valid_identity then
            certificate_score = 100;
        end

        local pubkey, keytype, bits = cert:pubkey();

        public_key_score = keysize_score(cert:pubkey());

        local sth = assert(dbh:prepare("UPDATE srv_results SET compression = ?, certificate_score = ?, valid_identity = ?, trusted = ? WHERE srv_result_id = ?"));
        assert(sth:execute(conn:info("compression"), certificate_score, valid_identity, chain_valid, srv_result_id));

        if conn:info("compression") then
            cap_compression = true;
        end

        dbh:commit();

        cert_done = true;
    end
end

local features_done = false;

function test_params(target, port, params, tlsa_answer, srv_result_id)
    local c = verse.new();
    local done = false;
    local ssl_done = false;

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
            c:close();
            return true;
        elseif event:get_child("not-authorized", "urn:ietf:params:xml:ns:xmpp-streams") then
            if not done then
                done = true;

                local info = c.conn:socket():info();

                verse.add_task(sleep_for, function ()
                    assert(coroutine.resume(co, info, "Remote did not trust our cert."));
                end);
            end
            c:close();
            return true;
        end
    end, 1000)

    c:hook("stream-features", function (features_stanza)
        local stanza = features_stanza:get_child("starttls", "urn:ietf:params:xml:ns:xmpp-tls");

        c:debug("Features!");

        got_sasl(srv_result_id, features_stanza, ssl_done);

        if not ssl_done then
            if stanza and stanza:get_child("required") then
                if not features_done then
                    features_done = true;

                    local sth = assert(dbh:prepare("UPDATE srv_results SET requires_starttls = ? WHERE srv_result_id = ?"));
                    assert(sth:execute(true, srv_result_id));

                    dbh:commit();
                end
            elseif stanza then
                if not features_done then
                    features_done = true;

                    local sth = assert(dbh:prepare("UPDATE srv_results SET requires_starttls = ? WHERE srv_result_id = ?"));
                    assert(sth:execute(false, srv_result_id));

                    dbh:commit();
                end
            else
                if not features_done then
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
        elseif not done then
            done = true;

            c:debug("Closing stream");
            
            local info = c.conn:socket():info();

            verse.add_task(1, function ()
                c:close();
            end);
            
            verse.add_task(sleep_for, function ()
                assert(coroutine.resume(co, info));
            end);

            return false;
        end
    end, 1000);

    c:hook("status", function (status)
        if status == "ssl-handshake-complete" then
            ssl_done = true;
            got_cert(c, tlsa_answer, srv_result_id);
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

local function test_server(target, port, co, tlsa_answer, srv_result_id)
    total_score = 0;
    public_key_score = 0;
    fail_untrusted = false;
    fail_ssl2 = false;
    cap_ssl3 = false;

    local params;

    local protocols = {};
    local lowest_protocol, highest_protocol;

    local info = nil;

    params = default_params;
    params.options = {"no_sslv3"};
    params.protocol = "sslv2";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    
    info = coroutine.yield();
    
    if info then
        protocols[#protocols + 1] = "sslv2";
        lowest_protocol = 20;
        highest_protocol = 20;
        fail_ssl2 = true;
    end
    
    params = deep_copy(default_params);
    params.options = {"no_sslv2"};
    params.protocol = "sslv3";
    test_params(target, port, params, tlsa_answer, srv_result_id);
    
    info = coroutine.yield();

    if info then
        protocols[#protocols + 1] = "sslv3";
        if not lowest_protocol then lowest_protocol = 80; end
        highest_protocol = 80;
        cap_ssl3 = true;
    end

    params = deep_copy(default_params);
    params.options = {"no_sslv3"};
    params.protocol = "tlsv1";
    test_params(target, port, params, tlsa_answer, srv_result_id);

    info = coroutine.yield();

    if info then
        protocols[#protocols + 1] = "tlsv1";
        if not lowest_protocol then lowest_protocol = 90; end
        highest_protocol = 90;
    end
    
    params = deep_copy(default_params);
    params.options = {"no_sslv3","no_tlsv1"};
    params.protocol = "tlsv1_1";
    test_params(target, port, params, tlsa_answer, srv_result_id);

    info = coroutine.yield();

    if info then
        protocols[#protocols + 1] = "tlsv1_1";
        if not lowest_protocol then lowest_protocol = 95; end
        highest_protocol = 95;
    end

    params = deep_copy(default_params);
    params.options = {"no_sslv3","no_tlsv1","no_tlsv1_1"};
    params.protocol = "tlsv1_2";
    test_params(target, port, params, tlsa_answer, srv_result_id);

    info = coroutine.yield();

    if info then
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

        if not info or err == "Remote did not trust our cert." then
            local sth = assert(dbh:prepare("UPDATE srv_results SET requires_peer_cert = '1' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();
        end
    end

    for k,v in ipairs(protocols) do
        -- v can only be sslv2, sslv3, tlsv1, tlsv1_1 or tlsv1_2, so this is fine. Really.
        local sth = assert(dbh:prepare("UPDATE srv_results SET " .. v .. " = '1' WHERE srv_result_id = ?"));
        assert(sth:execute(srv_result_id));
    end

    dbh:commit();

    if #protocols == 0 then
        local sth = assert(dbh:prepare("UPDATE srv_results SET error = ?, done = 't' WHERE srv_result_id = ? AND error IS NULL"));
        assert(sth:execute("Connection failed.", srv_result_id));
        dbh:commit();

        return
    end

    local protocol_score = (lowest_protocol + highest_protocol)/2;

    local sth = assert(dbh:prepare("UPDATE srv_results SET protocol_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(protocol_score, srv_result_id));

    dbh:commit();

    total_score = total_score + 0.3 * protocol_score;

    local cipher_string = "ALL:COMPLEMENTOFALL";
    local ciphers = {};
    local cipher_key_score_override = 100;

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

            log("debug", "Cipher strings: " .. cipher_string .. " cipher: " .. info.cipher);

            cipher_string = cipher_string .. ":!" .. info.cipher;

            if info.export then
                cipher_key_score_override = math.min(cipher_key_score_override, 40);
            end

            if info.tempalg == "DH" then
                if info.tempbits < 512 then
                    cipher_key_score_override = math.min(cipher_key_score_override, 20);
                elseif info.tempbits < 1024 then
                    cipher_key_score_override = math.min(cipher_key_score_override, 40);
                elseif info.tempbits < 2014 then
                    cipher_key_score_override = math.min(cipher_key_score_override, 80);
                elseif info.tempbits < 4096 then
                    cipher_key_score_override = math.min(cipher_key_score_override, 90);
                end
            end

            if info.authentication == "None" then
                cipher_key_score_override = 0;
            end

            if info.encryption == "RC4(128)" and (v == "tslv1_1" or v == "tlsv1_2") then
                warn_rc4_tls11 = true;
            end

            if info.cipher:find("ECDHE-") == 1 or info.cipher:find("DHE-") == 1 then
                warn_no_fs = false;
            end
       end
    end

    public_key_score = math.min(public_key_score, cipher_key_score_override);
    
    local sth = assert(dbh:prepare("UPDATE srv_results SET keysize_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(public_key_score, srv_result_id));

    dbh:commit();
    
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

        elseif result1.cipher == result2.cipher then
            should_sort = false;

            local sth = assert(dbh:prepare("UPDATE srv_results SET reorders_ciphers = '1' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();
        else
            local sth = assert(dbh:prepare("UPDATE srv_results SET reorders_ciphers = '0' WHERE srv_result_id = ?"));
            assert(sth:execute(srv_result_id));

            dbh:commit();
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

    local sth = assert(dbh:prepare("INSERT INTO srv_ciphers (srv_result_id, cipher_id, cipher_index, ecdh_curve, dh_bits, dh_group_id) VALUES (?, ?, ?, ?, ?, ?)"));
    local get_dh_group = assert(dbh:prepare("SELECT dh_group_id FROM dh_groups WHERE prime = decode(?, 'hex') AND generator = decode(?, 'hex')"));

    for k,v in ipairs(ciphers) do

        local dh_group_id = nil

        if v.tempalg == "DH" then
            assert(get_dh_group:execute(hex(v.dh_p), hex(v.dh_g)));

            dbh:commit()

            local results = get_dh_group:fetch()

            if not results or #results == 0 then
                dh_group_id, err = sql.execute_and_get_id(dbh, "INSERT INTO dh_groups (prime, generator) VALUES (decode(?, 'hex'), decode(?, 'hex'))", hex(v.dh_p), hex(v.dh_g));

                 -- A race condition, great. Lets retry the lookup.
                if err then
                    assert(get_dh_group:execute(hex(v.dh_p), hex(v.dh_g)));

                    dbh:commit();

                    dh_group_id = get_dh_group:fetch()[1]
                end
            else
                dh_group_id = results[1]
            end

            if v.tempbits < 2048 then
                cap_dh_2048 = true;
            end
        end

        assert(sth:execute(srv_result_id, ciphertable.find(v.cipher), k - 1, v.curve, v.tempalg == "DH" and v.tempbits or nil, dh_group_id));

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

    total_score = total_score + 0.4 * cipher_score;
    
    local sth = assert(dbh:prepare("UPDATE srv_results SET cipher_score = ? WHERE srv_result_id = ?"));
    assert(sth:execute(cipher_score, srv_result_id));

    dbh:commit();

    local function grade(score)
        if score >= 80 then return "A"; end
        if score >= 65 then return "B"; end
        if score >= 50 then return "C"; end
        if score >= 35 then return "D"; end
        if score >= 20 then return "E"; end
        return "F";
    end
    
    local final_grade = grade(total_score);

    if fail_ssl2 then
        final_grade = "F";
    end
    
    if fail_1024 then
        final_grade = "F";
    end
    
    if fail_md5 then
        final_grade = "F";
    end

    -- Fail servers that have SSL3 as their best protocol.
    if highest_protocol == 80 then
        final_grade = "F";
    end

    if cap_2048 then
        if final_grade == "A" then
            final_grade = "B";
        end
    end

    if cap_ssl3 then
        if final_grade == "A" then
            final_grade = "B"
        end
    end

    if cap_dh_2048 then
        if final_grade == "A" then
            final_grade = "B";
        end
    end

    if cap_compression then
        if final_grade == "A" or final_grade == "B" then
            final_grade = "C";
        end
    end

    -- Cap to C if RC4 is used with TLS 1.1+.
    if warn_rc4_tls11 then
        if final_grade == "A" or final_grade == "B" then
            final_grade = "C";
        end
    end

    -- Cap to C if not supporting TLS 1.2.
    if not (highest_protocol == 100) then
        if final_grade == "A" or final_grade == "B" then
            final_grade = "C";
        end
    end

    local sth = assert(dbh:prepare("UPDATE srv_results SET total_score = ?, grade = ?, done = '1', warn_rc4_tls11 = ?, warn_no_fs = ?, warn_dh_2048 = ? WHERE srv_result_id = ?"));
    assert(sth:execute(total_score, final_grade, warn_rc4_tls11, warn_no_fs, cap_dh_2048, srv_result_id));

    dbh:commit();

    return nil;
end

co = coroutine.create(function ()
    log("debug", "Starting DNS lookup.")

    local srv_records, err = adns.dns.lookup("_xmpp-" .. mode .. "._tcp." .. to_ascii(host), "SRV");
    
    if err then
        log("debug", "Resolving failed with error: " .. er)
        os.exit()
    end

    if version_jid and version_password then
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

        package.loaded["verse.client"] = nil;
    end

    verse = require("verse").init(mode);

    local stm = assert(dbh:prepare("UPDATE test_results SET srv_dnssec_good = ?, srv_dnssec_bogus = ? WHERE test_id = ?"));

    assert(stm:execute(srv_records and srv_records.secure, srv_records and not not srv_records.bogus, result_id));

    if not (srv_records and #srv_records > 0) then
        local port = (mode == "client" and 5222) or 5269;

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

        local tlsa = "_" .. srv.port .. "._tcp." .. srv.target;
        local tlsa_supported = (not require("net.dns").types) or (require("net.dns").types[52] == "TLSA");
        local tlsa_answer = nil;
        local srv_id;

        if tlsa_supported then

            local tlsa_answer, err = adns.dns.lookup(tlsa, "TLSA");

            srv_id = assert(sql.execute_and_get_id(dbh, q, result_id, srv.priority, srv.weight, srv.port, srv.target, tlsa_answer.secure, not not tlsa_answer.bogus));

            dbh:commit();
        else
            srv_id = assert(sql.execute_and_get_id(dbh, q, result_id, srv.priority, srv.weight, srv.port, srv.target, nil, nil));
        end

        test_server(srv.target, srv.port, co, tlsa_answer, srv_id);
    end

    dbh:commit();

    dbh:close();

    os.exit();
end)

verse.add_task(0, function ()
    assert(coroutine.resume(co));
end);

verse.add_task(30 * 60, function ()
    os.exit();
end);

verse.loop();
