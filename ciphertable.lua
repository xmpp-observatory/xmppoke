local M = {};

local ciphers = {};

ciphers[0xC030] = "ECDHE-RSA-AES256-GCM-SHA384";
ciphers[0xC02C] = "ECDHE-ECDSA-AES256-GCM-SHA384";
ciphers[0xC028] = "ECDHE-RSA-AES256-SHA384";
ciphers[0xC024] = "ECDHE-ECDSA-AES256-SHA384";
ciphers[0xC014] = "ECDHE-RSA-AES256-SHA";
ciphers[0xC00A] = "ECDHE-ECDSA-AES256-SHA";
ciphers[0xC022] = "SRP-DSS-AES-256-CBC-SHA";
ciphers[0xC021] = "SRP-RSA-AES-256-CBC-SHA";
ciphers[0x00A3] = "DHE-DSS-AES256-GCM-SHA384";
ciphers[0x009F] = "DHE-RSA-AES256-GCM-SHA384";
ciphers[0x006B] = "DHE-RSA-AES256-SHA256";
ciphers[0x006A] = "DHE-DSS-AES256-SHA256";
ciphers[0x0039] = "DHE-RSA-AES256-SHA";
ciphers[0x0038] = "DHE-DSS-AES256-SHA";
ciphers[0x0088] = "DHE-RSA-CAMELLIA256-SHA";
ciphers[0x0087] = "DHE-DSS-CAMELLIA256-SHA";
ciphers[0xC019] = "AECDH-AES256-SHA";
ciphers[0xC020] = "SRP-AES-256-CBC-SHA";
ciphers[0x00A7] = "ADH-AES256-GCM-SHA384";
ciphers[0x006D] = "ADH-AES256-SHA256";
ciphers[0x003A] = "ADH-AES256-SHA";
ciphers[0x0089] = "ADH-CAMELLIA256-SHA";
ciphers[0xC032] = "ECDH-RSA-AES256-GCM-SHA384";
ciphers[0xC02E] = "ECDH-ECDSA-AES256-GCM-SHA384";
ciphers[0xC02A] = "ECDH-RSA-AES256-SHA384";
ciphers[0xC026] = "ECDH-ECDSA-AES256-SHA384";
ciphers[0xC00F] = "ECDH-RSA-AES256-SHA";
ciphers[0xC005] = "ECDH-ECDSA-AES256-SHA";
ciphers[0x009D] = "AES256-GCM-SHA384";
ciphers[0x003D] = "AES256-SHA256";
ciphers[0x0035] = "AES256-SHA";
ciphers[0x0084] = "CAMELLIA256-SHA";
ciphers[0x008D] = "PSK-AES256-CBC-SHA";
ciphers[0xC012] = "ECDHE-RSA-DES-CBC3-SHA";
ciphers[0xC008] = "ECDHE-ECDSA-DES-CBC3-SHA";
ciphers[0xC01C] = "SRP-DSS-3DES-EDE-CBC-SHA";
ciphers[0xC01B] = "SRP-RSA-3DES-EDE-CBC-SHA";
ciphers[0x0016] = "EDH-RSA-DES-CBC3-SHA";
ciphers[0x0013] = "EDH-DSS-DES-CBC3-SHA";
ciphers[0xC017] = "AECDH-DES-CBC3-SHA";
ciphers[0xC01A] = "SRP-3DES-EDE-CBC-SHA";
ciphers[0x001B] = "ADH-DES-CBC3-SHA";
ciphers[0xC00D] = "ECDH-RSA-DES-CBC3-SHA";
ciphers[0xC003] = "ECDH-ECDSA-DES-CBC3-SHA";
ciphers[0x000A] = "DES-CBC3-SHA";
ciphers[0x0700C0] = "DES-CBC3-MD5";
ciphers[0x008B] = "PSK-3DES-EDE-CBC-SHA";
ciphers[0xC02F] = "ECDHE-RSA-AES128-GCM-SHA256";
ciphers[0xC02B] = "ECDHE-ECDSA-AES128-GCM-SHA256";
ciphers[0xC027] = "ECDHE-RSA-AES128-SHA256";
ciphers[0xC023] = "ECDHE-ECDSA-AES128-SHA256";
ciphers[0xC013] = "ECDHE-RSA-AES128-SHA";
ciphers[0xC009] = "ECDHE-ECDSA-AES128-SHA";
ciphers[0xC01F] = "SRP-DSS-AES-128-CBC-SHA";
ciphers[0xC01E] = "SRP-RSA-AES-128-CBC-SHA";
ciphers[0x00A2] = "DHE-DSS-AES128-GCM-SHA256";
ciphers[0x009E] = "DHE-RSA-AES128-GCM-SHA256";
ciphers[0x0067] = "DHE-RSA-AES128-SHA256";
ciphers[0x0040] = "DHE-DSS-AES128-SHA256";
ciphers[0x0033] = "DHE-RSA-AES128-SHA";
ciphers[0x0032] = "DHE-DSS-AES128-SHA";
ciphers[0x009A] = "DHE-RSA-SEED-SHA";
ciphers[0x0099] = "DHE-DSS-SEED-SHA";
ciphers[0x0045] = "DHE-RSA-CAMELLIA128-SHA";
ciphers[0x0044] = "DHE-DSS-CAMELLIA128-SHA";
ciphers[0xC018] = "AECDH-AES128-SHA";
ciphers[0xC01D] = "SRP-AES-128-CBC-SHA";
ciphers[0x00A6] = "ADH-AES128-GCM-SHA256";
ciphers[0x006C] = "ADH-AES128-SHA256";
ciphers[0x0034] = "ADH-AES128-SHA";
ciphers[0x009B] = "ADH-SEED-SHA";
ciphers[0x0046] = "ADH-CAMELLIA128-SHA";
ciphers[0xC031] = "ECDH-RSA-AES128-GCM-SHA256";
ciphers[0xC02D] = "ECDH-ECDSA-AES128-GCM-SHA256";
ciphers[0xC029] = "ECDH-RSA-AES128-SHA256";
ciphers[0xC025] = "ECDH-ECDSA-AES128-SHA256";
ciphers[0xC00E] = "ECDH-RSA-AES128-SHA";
ciphers[0xC004] = "ECDH-ECDSA-AES128-SHA";
ciphers[0x009C] = "AES128-GCM-SHA256";
ciphers[0x003C] = "AES128-SHA256";
ciphers[0x002F] = "AES128-SHA";
ciphers[0x0096] = "SEED-SHA";
ciphers[0x0041] = "CAMELLIA128-SHA";
ciphers[0x0007] = "IDEA-CBC-SHA";
ciphers[0x050080] = "IDEA-CBC-MD5";
ciphers[0x030080] = "RC2-CBC-MD5";
ciphers[0x008C] = "PSK-AES128-CBC-SHA";
ciphers[0xC011] = "ECDHE-RSA-RC4-SHA";
ciphers[0xC007] = "ECDHE-ECDSA-RC4-SHA";
ciphers[0xC016] = "AECDH-RC4-SHA";
ciphers[0x0018] = "ADH-RC4-MD5";
ciphers[0xC00C] = "ECDH-RSA-RC4-SHA";
ciphers[0xC002] = "ECDH-ECDSA-RC4-SHA";
ciphers[0x0005] = "RC4-SHA";
ciphers[0x0004] = "RC4-MD5";
ciphers[0x010080] = "RC4-MD5";
ciphers[0x008A] = "PSK-RC4-SHA";
ciphers[0x0015] = "EDH-RSA-DES-CBC-SHA";
ciphers[0x0012] = "EDH-DSS-DES-CBC-SHA";
ciphers[0x001A] = "ADH-DES-CBC-SHA";
ciphers[0x0009] = "DES-CBC-SHA";
ciphers[0x060040] = "DES-CBC-MD5";
ciphers[0x0014] = "EXP-EDH-RSA-DES-CBC-SHA";
ciphers[0x0011] = "EXP-EDH-DSS-DES-CBC-SHA";
ciphers[0x0019] = "EXP-ADH-DES-CBC-SHA";
ciphers[0x0008] = "EXP-DES-CBC-SHA";
ciphers[0x0006] = "EXP-RC2-CBC-MD5";
ciphers[0x040080] = "EXP-RC2-CBC-MD5";
ciphers[0x0017] = "EXP-ADH-RC4-MD5";
ciphers[0x0003] = "EXP-RC4-MD5";
ciphers[0x020080] = "EXP-RC4-MD5";
ciphers[0xC010] = "ECDHE-RSA-NULL-SHA";
ciphers[0xC006] = "ECDHE-ECDSA-NULL-SHA";
ciphers[0xC015] = "AECDH-NULL-SHA";
ciphers[0xC00B] = "ECDH-RSA-NULL-SHA";
ciphers[0xC001] = "ECDH-ECDSA-NULL-SHA";
ciphers[0x003B] = "NULL-SHA256";
ciphers[0x0002] = "NULL-SHA";
ciphers[0x0001] = "NULL-MD5";

M.ciphers = ciphers;

function M.find(name)
	for k,v in pairs(ciphers) do
		if v == name then
			return k
		end
	end
end

-- 00ffc00ac009c007c008c014c013c011c012c004c005c002c003c00ec00fc00cc00d002f000500040035000a003300390016

-- Turns a hex-dump of a TLS client hello message into the list of supported ciphers.
function M.parse_list_tls(str)
	local result = "";

	str:gsub("....", function (code)
		local cipher = ciphers[tonumber("0x" .. code)];
		if cipher then
			if #result > 0 then
				result = result .. ":";
			end
			result = result .. cipher;
		else
			print("Cipher " .. code .. " not found!");
		end
	end);

	return result;
end

return M;
