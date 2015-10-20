local lxp = require "lxp";
lxp.lom = require "lxp.lom";
local dbi = require "DBI";

local dbh = assert(dbi.Connect("PostgreSQL", "xmppoke", "xmppoke", "xmppoke", "localhost", 5432));
local stm = assert(dbh:prepare("SET TIMEZONE = 'UTC';"));
assert(stm:execute());

stm = assert(dbh:prepare("DELETE FROM public_servers;"));

assert(stm:execute());

for _,file in ipairs(arg) do
	local f = io.open(file, "r");

	print(file);

	local vcard = lxp.lom.parse(f:read("*a"));

	assert(vcard["tag"] == "vcard");

	local function get_child(t, nm)
		for k,v in ipairs(t) do
			if v.tag == nm then
				return v;
			end
		end
	end

	local function get_text(t)
		local result = "";
		for k,v in ipairs(t) do
			if type(v) == "string" then
				result = result .. v;
			end
		end
		return result;
	end

    local function render_attributes(t)
        local result = "";
        print(type(t), t);
        for k,v in ipairs(t.attr) do
                result = " " .. v .. "='" .. t.attr[v] .. "'"
        end
        return result;
    end

    local function render(t)
        if type(t) == "string" then
            return t;
        end
        local result = "<" .. t.tag .. render_attributes(t) .. ">"
        for k, v in ipairs(t) do
            result = result .. render(v);
        end
        return result .. "</" .. t.tag .. ">"
    end

	local fn = get_child(vcard, "fn");
	local name = get_child(fn, "text");

	local bday = get_child(vcard, "bday");
	local date = get_child(bday, "date");

	local adr = get_child(vcard, "adr");
	local country = get_child(adr, "country");

	local url = get_child(vcard, "url");
	local uri = get_child(url, "uri");

    local note = get_child(vcard, "note");
    local text = note and get_child(note, "text");

    local impp = get_child(vcard, "impp");
    local impp_uri = impp and get_child(impp, "uri");

    local vcard_rest = "";

    for k, v in ipairs(vcard) do
        if not (v.tag == "fn" or v.tag == "bday" or v.tag == "adr" or v.tag == "url" or v.tag == "note" or v.tag == "impp" or v.tag == "name" or v.tag == "ca") then
            vcard_rest = vcard_rest .. render(v)
        end
    end

    local stm = assert(dbh:prepare("INSERT INTO public_servers (server_name, founded, country, url, description, admin, vcard_rest) VALUES (?, ?, ?, ?, ?, ?, ?);"));

	assert(stm:execute(get_text(name), get_text(date), get_text(country), get_text(uri), text and get_text(text) or nil, impp_uri and get_text(impp_uri), vcard_rest));
end

dbh:commit();

dbh:close();