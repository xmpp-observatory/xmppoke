local short_opts = { v = "verbose", h = "html", o = "output", m = "mode", d = "delay" }
local opts = { mode = "client", html = false, output = "reports", verbose = false, delay = "2" };

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

for k,v in pairs(opts) do
    print(k,v)
end

if not host or (mode ~= "server" and mode ~= "client") then
    print(string.format("Usage: %s [-v] [-h] [-o output] [-m (server|client)] [-d=seconds] [hostname]", arg[0]));
    os.exit();
end

local jid = host;

local ssl = require("ssl");
local io = require("io");
local os = require("os");
local ciphertable = require("ciphertable");

local cert_verify_identity = require "util.x509".verify_identity;

local boldred, red, boldgreen, green, boldblue, reset;

if not use_html then
    boldred = string.char(0x1b) .. "[31;1m";
    red = string.char(0x1b) .. "[31m";
    boldgreen = string.char(0x1b) .. "[32;1m";
    green = string.char(0x1b) .. "[32m";
    boldblue = string.char(0x1b) .. "[34;1m";
    reset = string.char(0x1b) .. "[0m";
else
    boldred = "<span style='color: red; font-weight: bold;'>";
    red = "<span style='color: red'>";
    boldgreen = "<span style='color: green; font-weight: bold;'>";
    green = "<span style='color: green'>";
    boldblue = "<span style='color: blue; font-weight: bold;'>";
    reset= "</span>";
end

if use_html then
    report = io.open(opts.output .. "/" .. host .. ".html", "w");
    report:write("<html>");
    report:write("<head>");
    report:write("<title>XMPP TLS report for " .. host .. "</title>");
    report:write("</head>");
    report:write("");
    report:write("<body>");
    report:write("<pre>");
end

function print(str)
    print_no_nl(str .. "\n");
end

function print_no_nl(str)
    if use_html then
        report:write(str);
        report:flush();
    else
        io.stdout:write(str);
    end
end

function finish()
    if use_html then
        report:write("</pre>");
        report:write("</body>");
        report:write("</html>");
    end
end

local function line()
    if use_html then
        report:write("\n<hr />\n");
    else
        print("---");
    end
end

require("verse").init(mode);

if opts.verbose then
    verse.set_log_handler(function(part, level, str) io.stdout:write(part .. "  " .. level .. "\t\t" .. str .. "\n") end);
end

local total_score = 0;
local fail_untrusted = false;
local fail_ssl2 = false;

local function print_subject(print, subject)
    for _, entry in ipairs(subject) do
        print(("    %s: %q"):format(entry.name or entry.oid, entry.value:gsub("[\r\n%z%c]", " ")));
    end
end

local function _capitalize_and_colon(byte)
    return string.upper(byte)..":";
end

local function pretty_fingerprint(hash)
    return hash:gsub("..", _capitalize_and_colon):sub(1, -2);
end

local function print_errors(print, errors)
    if type(errors) == "string" then
        print("    0: " .. errors);
    else
        for depth, t in pairs(errors) do
            print(("    %d: %s"):format(depth-1, table.concat(t, "\n       ")));
        end
    end
end

local function keysize_score(bits)
    if bits == 0 then return 0; end
    if bits < 512 then return 20; end
    if bits < 1024 then return 40; end
    if bits < 2048 then return 80; end
    if bits < 4096 then return 90; end
    return 100;
end

function test_cert()
    local c = verse.new();
    local done = false;

    c.tlsparams = { mode = "client",
                    protocol = "sslv3",
                    verify = {"peer","fail_if_no_peer_cert"},
                    verifyext = {"lsec_continue", "crl_check_chain"},
                    cafile = "/opt/local/etc/openssl/cert.pem" };

    c:hook("status", function (status)
        if status == "ssl-handshake-complete" and not done then
            local conn = c.conn:socket();
            local cert = conn:getpeercertificate();

            line();

            print("Certificate details:");
            
            local chain_valid, errors = conn:getpeerverification();
            local valid_identity = cert_verify_identity(host, "xmpp-server", cert);
            print("Valid for "..host..": "..(valid_identity and "Yes" or boldred .. "No" .. reset));

            local chain_valid, errors = conn:getpeerverification();

            if chain_valid then
                print("Trusted certificate: Yes");
            else
                print("Trusted certificate: " .. red .. "No" .. reset);
                print_errors(print, errors);
                fail_untrusted = true;
            end

            if not valid_identity then
                fail_untrusted = true;
            end

            line();
            print("Certificate chain:");

            local i = 1;

            while true do
                local cert = conn:getpeercertificate(i);

                if not cert then break end;

                line();

                print(i-1 .. ":");

                print("Subject:");
                print_subject(print, cert:subject());

                print("");

                print("Fingerprint (SHA1): "..pretty_fingerprint(cert:digest("sha1")));

                local judgement = "";
                local signature_alg = cert:signature_alg();

                if signature_alg == "md5WithRSAEncryption" then
                    judgement = boldred .. " INSECURE!" .. reset;
                end

                print("");

                print("Signature algorithm: " .. cert:signature_alg() .. judgement);

                print("Key size: " .. cert:bits() .. " bits");

                print("");

                print("Valid from: " .. cert:notbefore());
                print("Valid to: " .. cert:notafter());

                local crl_url = cert:crl();
                local ocsp_url = cert:ocsp();

                print("Revocation:" .. (crl_url and  " CRL: " .. crl_url or "") .. (ocsp_url and  " OCSP: " .. ocsp_url or ""));

                i = i + 1;
            end

            line();

            local last_cert = conn:getpeercertificate(i - 1);

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

            -- Hack: if the subject is identical, we assume the server sent its root CA too.
            if deep_equal(last_cert:issuer(), last_cert:subject()) then
                print(red .. "Root CA certificate was included in chain." .. reset);
            else
                print("Root CA: ");
                print_subject(print, last_cert:issuer());
            end

            local certificate_score = 0;

            if chain_valid and valid_identity then
                certificate_score = 100;
            end

            line();

            print(green .. "Certificate score: " .. certificate_score .. reset);
            print(green .. "Key exchange score: " .. keysize_score(cert:bits()) .. reset);

            total_score = total_score + 0.3 * keysize_score(cert:bits());

            line();
            print("Compression: " .. (conn:info("compression") or "none"));
            line();

            done = true;

            c:debug("Closing stream");
            c.conn:socket():close();
            
            verse.add_task(sleep_for, function ()
                coroutine.resume(co);
            end);
        end
        return false;
    end, 1000);

    c:hook("disconnected", function ()
        if not done then
            done = true;
            verse.add_task(sleep_for, function ()
                coroutine.resume(co, nil, "Disconnected");
            end);
        end
    end);

    c:connect_client(jid);
end

function test_params(params)
    local c = verse.new();
    local done = false;

    c.tlsparams = params;

    c:hook("status", function (status)
        if status == "ssl-handshake-complete" and not done then
            local info = c.conn:socket():info();

            done = true;

            c:debug("Closing stream");
            c.conn:socket():close();
            
            verse.add_task(sleep_for, function ()
                coroutine.resume(co, info);
            end);
        end
        return false;
    end, 1000);

    c:hook("disconnected", function ()
        if not done then
            done = true;
            verse.add_task(sleep_for, function ()
                coroutine.resume(co, nil, "Disconnected");
            end);
        end
    end);

    c:connect_client(jid);
end

local function color_bits(bits)
    if bits < 128 then
        return boldred .. bits .. reset;
    elseif bits < 256 then
        return green .. bits .. reset;
    else
        return boldgreen .. bits .. reset;
    end
end

local function pretty_cipher(info)
    local judgement = ""

    if info.bits < 128 then
        judgement = boldred .. " WEAK!" .. reset
    end

    if info.cipher:find("ECDHE-") == 1 or info.cipher:find("DHE-") == 1 then
        judgement = judgement .. boldblue .. " FS" .. reset
    end

    return info.protocol .. " " .. info.cipher .. " (" .. color_bits(info.bits) .. ") " .. string.format("0x%02X", ciphertable.find(info.cipher)) .. judgement;
end

local function print_result(info, err)
    if err then
        print(red .. "Fail: " .. err .. reset);
        return false;
    else
        print("OK: " .. pretty_cipher(info));
        return true;
    end
end

co = coroutine.create(function ()
    test_cert();

    coroutine.yield();

    local protocols = {};
    local lowest_protocol, highest_protocol;

    print("Testing protocol support:");
    print_no_nl("Testing SSLv2 support... ");
    test_params({ mode = "client", options = {"no_sslv3"}, protocol = "sslv2" });
    if print_result(coroutine.yield()) then
        protocols[#protocols + 1] = "sslv2";
        lowest_protocol = 20;
        highest_protocol = 20;
        fail_ssl2 = true;
    end
    
    print_no_nl("Testing SSLv3 support... ");
    test_params({ mode = "client", options = {"no_sslv2"}, protocol = "sslv3" });
    if print_result(coroutine.yield()) then
        protocols[#protocols + 1] = "sslv3";
        if not lowest_protocol then lowest_protocol = 80; end
        highest_protocol = 80;
    end

    print_no_nl("Testing TLSv1 support... ");
    test_params({ mode = "client", options = {"no_sslv3"}, protocol = "tlsv1" });
    if print_result(coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1";
        if not lowest_protocol then lowest_protocol = 90; end
        highest_protocol = 90;
    end
   
    print_no_nl("Testing TLSv1.1 support... ");
    test_params({ mode = "client", options = {"no_sslv3","no_tlsv1"}, protocol = "tlsv1_1" });
    if print_result(coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1_1";
        if not lowest_protocol then lowest_protocol = 95; end
        highest_protocol = 95;
    end

    print_no_nl("Testing TLSv1.2 support... ");
    test_params({ mode = "client", options = {"no_sslv3","no_tlsv1","no_tlsv1_1"}, protocol = "tlsv1_2" });
    if print_result(coroutine.yield()) then
        protocols[#protocols + 1] = "tlsv1_2";
        if not lowest_protocol then lowest_protocol = 100; end
        highest_protocol = 100;
    end

    local protocol_score = (lowest_protocol + highest_protocol)/2;

    print(green .. "Protocol score: " .. protocol_score .. reset);

    total_score = total_score + 0.3 * protocol_score;

    line();
    print("Determining cipher support:");

    local cipher_string = "ALL:COMPLEMENTOFALL";
    local ciphers = {};

    for i=#protocols,1,-1 do
        local v = protocols[i];
        while true do
            test_params({ mode = "client", options = {}, protocol = v, ciphers = cipher_string });

            local info, err = coroutine.yield();

            if not info then break end;

            ciphers[#ciphers + 1] = info;

            cipher_string = cipher_string .. ":!" .. info.cipher;
       end
    end

    local should_sort = true;

    if #ciphers > 1 then
        local cipher1 = ciphers[1];
        local cipher2 = ciphers[2];
        local protocol = protocols[#protocols];

        params = { mode = "client", protocol = protocol };
        params.ciphers = cipher1.cipher .. ":" .. cipher2.cipher;
        test_params(params);
        local result1 = coroutine.yield();

        params = { mode = "client", protocol = protocol };
        params.ciphers = cipher2.cipher .. ":" .. cipher1.cipher;
        test_params(params);
        local result2 = coroutine.yield();

        if not result1 or not result2 then
            print(red .. "Problem with testing server's ordering." .. reset);
        elseif result1.cipher == result2.cipher then
            print("Server does " .. red .. "not" .. reset .. " respect client's cipher ordering. Server's order:");
            should_sort = false;
        else
            print("Server does respect client's cipher ordering.");
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

    for k,v in ipairs(ciphers) do
        print(pretty_cipher(v));
        if v.bits < min_bits then min_bits = v.bits; end;
        if v.bits > max_bits then max_bits = v.bits; end;
    end

    local function cipher_score(bits)
        if bits == 0 then return 0 end
        if bits < 128 then return 20 end
        if bits < 256 then return 80 end
        return 100
    end

    local cipher_score = (cipher_score(max_bits) + cipher_score(min_bits))/2;

    print(green .. "Cipher score: " .. cipher_score .. reset);

    total_score = total_score + 0.4 * cipher_score;

    if mode == "client" then

        line();
        print("Estimating client support:");

        print_no_nl("Simulating Adium 1.5.7 on OS X 10.8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:EXP-RC4-MD5:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Adium 1.5.8hg on OS X 10.8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2"} };
        params.ciphers = "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA";
        test_params(params);
        print_result(coroutine.yield());    

        print_no_nl("Simulating Pidgin 2.10.7 on Windows 8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:DSS-RC4-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:SSL_RSA_FIPS_WITH_DES_CBC_SHA:DES-CBC-SHA:EXP1024-RC4-SHA:EXP1024-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC2-CBC-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Gajim 0.15.4 on Windows 8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:IDEA-CBC-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Jitsi 2.2.4603.9615 on Windows 8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDH-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Jitsi 2.2.4603.9615 on OS X 10.8... ");

        params = { mode = "client", protocol = "sslv23", options = {"no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "RC4-MD5:RC4-MD5:RC4-SHA:AES128-SHA:AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DES-CBC3-SHA:DES-CBC3-MD5:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC-SHA:DES-CBC-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Psi 0.15 on OS X 10.8... ");

        params = { mode = "client", protocol = "sslv23", options = {"no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA:RC2-CBC-MD5:RC4-SHA:RC4-MD5:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-RC4-MD5:EXP-RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Messages 7.0.1 (3322) on OS X 10.8... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2"} };
        params.ciphers = "ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:AES128-SHA:RC4-SHA:RC4-MD5:AES256-SHA:DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:EDH-RSA-DES-CBC3-SHA";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Pidgin 2.10.6 on Debian 7.1... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2"} };
        params.ciphers = "DHE-DSS-AES256-SHA:AES256-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:RC4-SHA:RC4-MD5:AES128-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:DES-CBC3-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Gajim 0.15.1 on Debian 7.1... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2"} };
        params.ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Empathy 3.4.2.3 on Debian 7.1... ");

        params = { mode = "client", protocol = "sslv3", options = {"no_sslv2"} };
        params.ciphers = "DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:AES128-SHA:AES128-SHA256:CAMELLIA128-SHA:AES256-SHA:AES256-SHA256:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Swift 2.0beta1-dev47 on Debian 7.1... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2", "no_tlsv1_1", "no_tlsv1_2" } };
        params.ciphers = "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating Psi 0.14 on Debian 7.1... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2"} };
        params.ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:DES-CBC-SHA:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

        print_no_nl("Simulating irssi-xmpp 0.52 on Debian 7.1... ");

        params = { mode = "client", protocol = "tlsv1", options = {"no_sslv2"} };
        params.ciphers = "DHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-CAMELLIA128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-CAMELLIA256-SHA:EDH-RSA-DES-CBC3-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-DSS-CAMELLIA128-SHA:DHE-DSS-AES256-SHA:DHE-DSS-AES256-SHA256:DHE-DSS-CAMELLIA256-SHA:EDH-DSS-DES-CBC3-SHA:AES128-SHA:AES128-SHA256:CAMELLIA128-SHA:AES256-SHA:AES256-SHA256:CAMELLIA256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5";
        test_params(params);
        print_result(coroutine.yield());

    end


    local function grade(score)
        if score >= 80 then return "A"; end
        if score >= 65 then return "B"; end
        if score >= 50 then return "C"; end
        if score >= 35 then return "D"; end
        if score >= 20 then return "E"; end
        return "F";
    end

    line();
    print(green .. "Total score: " .. total_score);
    if fail_untrusted then
        print(red .. "Grade: F (Untrusted certificate)" .. reset);
        print(green .. "When ignoring trust: ");
    end
    if fail_ssl2 then
        print(red .. "Grade set to F due to support for obsolete and insecure SSLv2." .. reset);
    else
        print("Grade: " .. grade(total_score) .. reset);
    end

    local log = io.open("scores.log", "a");

    local score = grade(total_score);

    if fail_untrusted or fail_ssl2 then
        score = "F";
    end

    log:write(host .. "\t" .. total_score .. "\t" .. score .. "\t" .. os.time() .. "\n");

    log:flush();

    log:close();

    finish();

    os.exit();
end)

verse.add_task(0, function ()
    coroutine.resume(co);
end);

verse.loop();
