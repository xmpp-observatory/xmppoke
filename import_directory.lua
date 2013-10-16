local lxp = require "lxp";
lxp.lom = require "lxp.lom";
local dbi = require "DBI";

local dbh = assert(dbi.Connect("PostgreSQL", "xmppoke", "xmppoke", "xmppoke", "localhost", 5433));
local stm = assert(dbh:prepare("SET TIMEZONE = 'UTC';"));
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

	local fn = get_child(vcard, "fn");
	local name = get_child(fn, "text");

	local bday = get_child(vcard, "bday");
	local date = get_child(bday, "date");

	local adr = get_child(vcard, "adr");
	local country = get_child(adr, "country");

	local url = get_child(vcard, "url");
	local uri = get_child(url, "uri");

	local stm = assert(dbh:prepare("INSERT INTO public_servers (server_name, founded, country, url) VALUES (?, ?, ?, ?);"));

	assert(stm:execute(get_text(name), get_text(date), get_text(country), get_text(uri)));
end

dbh:commit();

dbh:close();