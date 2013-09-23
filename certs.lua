local date = require("3rdparty/date");
local sha1 = require("util.hashes").sha1;
local openssl_blacklists = nil;

function print_subject(print, subject)
    for _, entry in ipairs(subject) do
        print(("    %s: %q"):format(entry.name or entry.oid, entry.value:gsub("[\r\n%z%c]", " ")));
    end
end

local function _capitalize_and_colon(byte)
    return string.upper(byte)..":";
end

function pretty_fingerprint(hash)
    return hash:gsub("..", _capitalize_and_colon):sub(1, -2);
end

function tohex(c)
    return string.format("%02x", string.byte(c));
end

function print_errors(print, errors)
    if type(errors) == "string" then
        print("    0: " .. errors);
    else
        for depth, t in pairs(errors) do
            print(("    %d: %s"):format(depth-1, table.concat(t, "\n       ")));
        end
    end
end

function debian_weak_key(cert)
    local bits = cert:bits();
    local modulus_hash = sha1("Modulus="..cert:modulus().."\n"):gsub(".", tohex);

    local blacklist = openssl_blacklists and io.open(openssl_blacklists .. "/blacklist.RSA-" .. bits) or nil;

    if blacklist then
        local found = false;

        while true do
            local line = blacklist:read("*l");

            if not line then break; end

            if line == modulus_hash:sub(20) then
                return true;
            end
        end

        return false;
    end

    return nil;
end

function pretty_cert(outputmanager, current_cert)
    outputmanager.print("Subject:");
    print_subject(outputmanager.print, current_cert:subject());

    outputmanager.print("");

    outputmanager.print("SubjectPublicKeyInfo: "..current_cert:spki():gsub(".", tohex));

    outputmanager.print("Fingerprint (SHA1): "..pretty_fingerprint(current_cert:digest("sha1")));
    outputmanager.print("Fingerprint (SHA256): "..pretty_fingerprint(current_cert:digest("sha256")));
    outputmanager.print("Fingerprint (SHA512): "..pretty_fingerprint(current_cert:digest("sha512")));

    local bits = current_cert:bits();
    local b = debian_weak_key(current_cert);
    
    if b then
        outputmanager.print(outputmanager.boldred .. "Uses a weak Debian key! See https://wiki.debian.org/SSLkeys" .. outputmanager.reset);
    elseif b == nil then
        outputmanager.print("Can not determine whether a key with bit size " .. bits .. " is a weak Debian key.");
    end

    local judgement = "";
    local signature_alg = current_cert:signature_alg();

    if signature_alg == "md5WithRSAEncryption" then
        judgement = outputmanager.boldred .. " INSECURE!" .. outputmanager.reset;
    end

    outputmanager.print("");

    outputmanager.print("Signature algorithm: " .. signature_alg .. judgement);

    outputmanager.print("Key size: " .. bits .. " bits");

    outputmanager.print("");

    local notbefore = date(current_cert:notbefore());
    local notafter = date(current_cert:notafter());
    local now = date();

    outputmanager.print("Valid from: " .. notbefore:fmt("%F %T GMT") .. " (" .. date.fuzzy_range(now, notbefore) .. ")");
    outputmanager.print("Valid to: " .. notafter:fmt("%F %T GMT") .. " (" .. date.fuzzy_range(now, notafter) .. ")");

    if now < notbefore then
        outputmanager.print(outputmanager.boldred .. "Certificate is not yet valid." .. outputmanager.reset);
    end
    if now > notafter then
        outputmanager.print(outputmanager.boldred .. "Certificate is outputmanager.expired." .. outputmanager.reset);
    end

    local crl_url = current_cert:crl();
    local ocsp_url = current_cert:ocsp();

    outputmanager.print("Revocation:" .. (crl_url and  " CRL: " .. crl_url or "") .. (ocsp_url and  " OCSP: " .. ocsp_url or ""));
end

return function(blacklist)
    openssl_blacklists = blacklist;
    return {
        print_subject = print_subject;
        pretty_fingerprint = pretty_fingerprint;
        print_errors = print_errors;
        pretty_cert = pretty_cert;
        tohex = tohex;
    }
end