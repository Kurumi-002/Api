--[[
    Secret Service Syn Library
    written by @ex_ren
]]

assert(getgenv, "Executor not supported")

local genv = getgenv()
local cloneref = typeof(cloneref) == "function" and cloneref or function(x)
	return x
end

local _hookfunction = genv.hookfunction or genv.hookfunc or genv.detour_function
local _restorefunction = genv.restorefunction or genv.restorefunc or genv.unhookfunction
local _newcclosure = genv.newcclosure or function(f)
	return f
end
local _clonefunction = genv.clonefunction or genv.clonefunc
local _isfunctionhooked = genv.isfunctionhooked
local _request = genv.request or genv.http_request or (http and http.request) or (fluxus and fluxus.request)
local _clipboard = genv.setclipboard or genv.toclipboard or genv.set_clipboard
local _queueteleport = genv.queue_on_teleport or (fluxus and fluxus.queue_on_teleport)
local _setidentity = genv.setthreadidentity or genv.setthreadcontext or genv.syn_context_set or genv.setidentity
local _getidentity = genv.getthreadidentity or genv.getthreadcontext or genv.syn_context_get or genv.getidentity
local _gethui = genv.gethui or genv.get_hidden_gui
local _getgc = genv.getgc
local _getfenv = genv.getfenv or getfenv
local _setfenv = genv.setfenv or setfenv
local _getsenv = genv.getsenv
local _getcallingscript = genv.getcallingscript
local _checkcaller = genv.checkcaller
local _getnamecallmethod = genv.getnamecallmethod
local _setnamecallmethod = genv.setnamecallmethod
local _runonactor = genv.run_on_actor
local _hooksignal = genv.hooksignal
local _restoresignal = genv.restoresignal
local _issignalhooked = genv.issignalhooked
local _hookproto = genv.hookproto
local _restoreproto = genv.restoreproto
local _hookmetamethod = genv.hookmetamethod
local _WebSocket = genv.WebSocket

local loader = loadstring or load
assert(typeof(_request) == "function", "No HTTP request function found")

local services = setmetatable({}, {
	__index = function(self, name)
		local svc = cloneref(game:GetService(name))
		rawset(self, name, svc)
		return svc
	end,
})

local band = bit32.band
local bxor = bit32.bxor
local bnot = bit32.bnot
local rrotate = bit32.rrotate
local rshift = bit32.rshift
local lshift = bit32.lshift
local bor = bit32.bor

local function num2s(l, n)
	local s = ""
	for _ = 1, n do
		local rem = l % 256
		s = string.char(rem) .. s
		l = (l - rem) / 256
	end
	return s
end

local function s232num(s, i)
	local n = 0
	for j = i, i + 3 do
		n = n * 256 + string.byte(s, j)
	end
	return n
end

local K256 = {
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2,
}

local function sha256_block(msg, i, H)
	local w = {}
	for j = 1, 16 do
		w[j] = s232num(msg, i + (j - 1) * 4)
	end
	for j = 17, 64 do
		local v15, v2 = w[j - 15], w[j - 2]
		w[j] = w[j - 16]
			+ bxor(rrotate(v15, 7), rrotate(v15, 18), rshift(v15, 3))
			+ w[j - 7]
			+ bxor(rrotate(v2, 17), rrotate(v2, 19), rshift(v2, 10))
	end
	local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
	for j = 1, 64 do
		local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
		local ch = bxor(band(e, f), band(bnot(e), g))
		local t1 = h + s1 + ch + K256[j] + w[j]
		local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
		local maj = bxor(band(a, b), band(a, c), band(b, c))
		h, g, f, e, d, c, b, a = g, f, e, d + t1, c, b, a, t1 + s0 + maj
	end
	H[1] = band(H[1] + a)
	H[2] = band(H[2] + b)
	H[3] = band(H[3] + c)
	H[4] = band(H[4] + d)
	H[5] = band(H[5] + e)
	H[6] = band(H[6] + f)
	H[7] = band(H[7] + g)
	H[8] = band(H[8] + h)
end

local function sha256_raw(msg)
	local len = #msg
	msg = msg .. "\128" .. string.rep("\0", 64 - ((len + 9) % 64)) .. num2s(8 * len, 8)
	local H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
	for i = 1, #msg, 64 do
		sha256_block(msg, i, H)
	end
	return num2s(H[1], 4)
		.. num2s(H[2], 4)
		.. num2s(H[3], 4)
		.. num2s(H[4], 4)
		.. num2s(H[5], 4)
		.. num2s(H[6], 4)
		.. num2s(H[7], 4)
		.. num2s(H[8], 4)
end

local function sha256_hex(msg)
	return (sha256_raw(msg):gsub(".", function(c)
		return string.format("%02x", string.byte(c))
	end))
end

local function hmac_sha256(key, msg)
	if #key > 64 then
		key = sha256_raw(key)
	end
	key = key .. string.rep("\0", 64 - #key)
	local opad, ipad = {}, {}
	for i = 1, 64 do
		local kb = string.byte(key, i)
		opad[i] = string.char(bxor(kb, 0x5c))
		ipad[i] = string.char(bxor(kb, 0x36))
	end
	return sha256_raw(table.concat(opad) .. sha256_raw(table.concat(ipad) .. msg))
end

local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function b64_encode(data)
	return (
		(data:gsub(".", function(x)
			local r, b = "", x:byte()
			for i = 8, 1, -1 do
				r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0")
			end
			return r
		end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
			if #x < 6 then
				return ""
			end
			local c = 0
			for i = 1, 6 do
				c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0)
			end
			return B64:sub(c + 1, c + 1)
		end) .. ({ "", "==", "=" })[#data % 3 + 1]
	)
end

local function b64_decode(data)
	data = data:gsub("[^" .. B64 .. "=]", "")
	return (
		data:gsub(".", function(x)
			if x == "=" then
				return ""
			end
			local r, f = "", (B64:find(x) - 1)
			for i = 6, 1, -1 do
				r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and "1" or "0")
			end
			return r
		end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(x)
			if #x ~= 8 then
				return ""
			end
			local c = 0
			for i = 1, 8 do
				c = c + (x:sub(i, i) == "1" and 2 ^ (8 - i) or 0)
			end
			return string.char(c)
		end)
	)
end

local function hex_encode(d)
	return (d:gsub(".", function(c)
		return string.format("%02x", string.byte(c))
	end))
end

local function hex_decode(d)
	return (d:gsub("%x%x", function(h)
		return string.char(tonumber(h, 16))
	end))
end

local function url_encode(d)
	return (d:gsub("[^%w%-_.~]", function(c)
		return string.format("%%%02X", string.byte(c))
	end))
end

local function url_decode(d)
	return (d:gsub("%%(%x%x)", function(h)
		return string.char(tonumber(h, 16))
	end):gsub("+", " "))
end

local SBOX = {
	0x63,
	0x7c,
	0x77,
	0x7b,
	0xf2,
	0x6b,
	0x6f,
	0xc5,
	0x30,
	0x01,
	0x67,
	0x2b,
	0xfe,
	0xd7,
	0xab,
	0x76,
	0xca,
	0x82,
	0xc9,
	0x7d,
	0xfa,
	0x59,
	0x47,
	0xf0,
	0xad,
	0xd4,
	0xa2,
	0xaf,
	0x9c,
	0xa4,
	0x72,
	0xc0,
	0xb7,
	0xfd,
	0x93,
	0x26,
	0x36,
	0x3f,
	0xf7,
	0xcc,
	0x34,
	0xa5,
	0xe5,
	0xf1,
	0x71,
	0xd8,
	0x31,
	0x15,
	0x04,
	0xc7,
	0x23,
	0xc3,
	0x18,
	0x96,
	0x05,
	0x9a,
	0x07,
	0x12,
	0x80,
	0xe2,
	0xeb,
	0x27,
	0xb2,
	0x75,
	0x09,
	0x83,
	0x2c,
	0x1a,
	0x1b,
	0x6e,
	0x5a,
	0xa0,
	0x52,
	0x3b,
	0xd6,
	0xb3,
	0x29,
	0xe3,
	0x2f,
	0x84,
	0x53,
	0xd1,
	0x00,
	0xed,
	0x20,
	0xfc,
	0xb1,
	0x5b,
	0x6a,
	0xcb,
	0xbe,
	0x39,
	0x4a,
	0x4c,
	0x58,
	0xcf,
	0xd0,
	0xef,
	0xaa,
	0xfb,
	0x43,
	0x4d,
	0x33,
	0x85,
	0x45,
	0xf9,
	0x02,
	0x7f,
	0x50,
	0x3c,
	0x9f,
	0xa8,
	0x51,
	0xa3,
	0x40,
	0x8f,
	0x92,
	0x9d,
	0x38,
	0xf5,
	0xbc,
	0xb6,
	0xda,
	0x21,
	0x10,
	0xff,
	0xf3,
	0xd2,
	0xcd,
	0x0c,
	0x13,
	0xec,
	0x5f,
	0x97,
	0x44,
	0x17,
	0xc4,
	0xa7,
	0x7e,
	0x3d,
	0x64,
	0x5d,
	0x19,
	0x73,
	0x60,
	0x81,
	0x4f,
	0xdc,
	0x22,
	0x2a,
	0x90,
	0x88,
	0x46,
	0xee,
	0xb8,
	0x14,
	0xde,
	0x5e,
	0x0b,
	0xdb,
	0xe0,
	0x32,
	0x3a,
	0x0a,
	0x49,
	0x06,
	0x24,
	0x5c,
	0xc2,
	0xd3,
	0xac,
	0x62,
	0x91,
	0x95,
	0xe4,
	0x79,
	0xe7,
	0xc8,
	0x37,
	0x6d,
	0x8d,
	0xd5,
	0x4e,
	0xa9,
	0x6c,
	0x56,
	0xf4,
	0xea,
	0x65,
	0x7a,
	0xae,
	0x08,
	0xba,
	0x78,
	0x25,
	0x2e,
	0x1c,
	0xa6,
	0xb4,
	0xc6,
	0xe8,
	0xdd,
	0x74,
	0x1f,
	0x4b,
	0xbd,
	0x8b,
	0x8a,
	0x70,
	0x3e,
	0xb5,
	0x66,
	0x48,
	0x03,
	0xf6,
	0x0e,
	0x61,
	0x35,
	0x57,
	0xb9,
	0x86,
	0xc1,
	0x1d,
	0x9e,
	0xe1,
	0xf8,
	0x98,
	0x11,
	0x69,
	0xd9,
	0x8e,
	0x94,
	0x9b,
	0x1e,
	0x87,
	0xe9,
	0xce,
	0x55,
	0x28,
	0xdf,
	0x8c,
	0xa1,
	0x89,
	0x0d,
	0xbf,
	0xe6,
	0x42,
	0x68,
	0x41,
	0x99,
	0x2d,
	0x0f,
	0xb0,
	0x54,
	0xbb,
	0x16,
}
local INV_SBOX = {}
for i = 0, 255 do
	INV_SBOX[SBOX[i + 1]] = i
end
local RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

local function sub_word(w)
	return bor(
		lshift(SBOX[rshift(w, 24) + 1], 24),
		lshift(SBOX[band(rshift(w, 16), 0xFF) + 1], 16),
		lshift(SBOX[band(rshift(w, 8), 0xFF) + 1], 8),
		SBOX[band(w, 0xFF) + 1]
	)
end

local function aes_expand(key)
	local nk = #key / 4
	local nr = nk + 6
	local W = {}
	for i = 0, nk - 1 do
		W[i] = s232num(key, i * 4 + 1)
	end
	for i = nk, 4 * (nr + 1) - 1 do
		local t = W[i - 1]
		if i % nk == 0 then
			t = bxor(sub_word(bor(lshift(band(t, 0x00FFFFFF), 8), rshift(t, 24))), lshift(RCON[i / nk], 24))
		elseif nk > 6 and i % nk == 4 then
			t = sub_word(t)
		end
		W[i] = bxor(W[i - nk], t)
	end
	return W, nr
end

local function gmul(a, b)
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then
			p = bxor(p, a)
		end
		local hi = band(a, 0x80)
		a = band(lshift(a, 1), 0xFF)
		if hi ~= 0 then
			a = bxor(a, 0x1b)
		end
		b = rshift(b, 1)
	end
	return p
end

local function str2bytes(s)
	local t = {}
	for i = 1, #s do
		t[i] = string.byte(s, i)
	end
	return t
end

local function bytes2str(t)
	local s = {}
	for i = 1, #t do
		s[i] = string.char(t[i])
	end
	return table.concat(s)
end

local function aes_enc_block(state, W, nr)
	local s = {}
	for i = 0, 15 do
		s[i] = bxor(state[i + 1], band(rshift(W[math.floor(i / 4)], (3 - i % 4) * 8), 0xFF))
	end
	for round = 1, nr do
		local t = {}
		for i = 0, 15 do
			t[i] = SBOX[s[i] + 1]
		end
		local u = {}
		u[0], u[1], u[2], u[3] = t[0], t[5], t[10], t[15]
		u[4], u[5], u[6], u[7] = t[4], t[9], t[14], t[3]
		u[8], u[9], u[10], u[11] = t[8], t[13], t[2], t[7]
		u[12], u[13], u[14], u[15] = t[12], t[1], t[6], t[11]
		if round < nr then
			local m = {}
			for col = 0, 3 do
				local b0, b1, b2, b3 = u[col * 4], u[col * 4 + 1], u[col * 4 + 2], u[col * 4 + 3]
				m[col * 4] = bxor(gmul(b0, 2), gmul(b1, 3), b2, b3)
				m[col * 4 + 1] = bxor(b0, gmul(b1, 2), gmul(b2, 3), b3)
				m[col * 4 + 2] = bxor(b0, b1, gmul(b2, 2), gmul(b3, 3))
				m[col * 4 + 3] = bxor(gmul(b0, 3), b1, b2, gmul(b3, 2))
			end
			u = m
		end
		local rk = round * 4
		for i = 0, 15 do
			s[i] = bxor(u[i], band(rshift(W[rk + math.floor(i / 4)], (3 - i % 4) * 8), 0xFF))
		end
	end
	local out = {}
	for i = 0, 15 do
		out[i + 1] = s[i]
	end
	return out
end

local function aes_dec_block(state, W, nr)
	local s = {}
	local rk = nr * 4
	for i = 0, 15 do
		s[i] = bxor(state[i + 1], band(rshift(W[rk + math.floor(i / 4)], (3 - i % 4) * 8), 0xFF))
	end
	for round = nr - 1, 0, -1 do
		local u = {}
		u[0], u[1], u[2], u[3] = s[0], s[13], s[10], s[7]
		u[4], u[5], u[6], u[7] = s[4], s[1], s[14], s[11]
		u[8], u[9], u[10], u[11] = s[8], s[5], s[2], s[15]
		u[12], u[13], u[14], u[15] = s[12], s[9], s[6], s[3]
		local t = {}
		for i = 0, 15 do
			t[i] = INV_SBOX[u[i]]
		end
		local rkr = round * 4
		for i = 0, 15 do
			s[i] = bxor(t[i], band(rshift(W[rkr + math.floor(i / 4)], (3 - i % 4) * 8), 0xFF))
		end
		if round > 0 then
			local m = {}
			for col = 0, 3 do
				local b0, b1, b2, b3 = s[col * 4], s[col * 4 + 1], s[col * 4 + 2], s[col * 4 + 3]
				m[col * 4] = bxor(gmul(b0, 14), gmul(b1, 11), gmul(b2, 13), gmul(b3, 9))
				m[col * 4 + 1] = bxor(gmul(b0, 9), gmul(b1, 14), gmul(b2, 11), gmul(b3, 13))
				m[col * 4 + 2] = bxor(gmul(b0, 13), gmul(b1, 9), gmul(b2, 14), gmul(b3, 11))
				m[col * 4 + 3] = bxor(gmul(b0, 11), gmul(b1, 13), gmul(b2, 9), gmul(b3, 14))
			end
			s = m
		end
	end
	local out = {}
	for i = 0, 15 do
		out[i + 1] = s[i]
	end
	return out
end

local function pkcs7_pad(d)
	local p = 16 - (#d % 16)
	return d .. string.rep(string.char(p), p)
end
local function pkcs7_unpad(d)
	local p = string.byte(d, #d)
	if p < 1 or p > 16 then
		return d
	end
	return d:sub(1, #d - p)
end

local function normalize_key(key)
	if #key ~= 16 and #key ~= 24 and #key ~= 32 then
		return sha256_raw(key)
	end
	return key
end

local function aes_cbc_enc(plain, key, iv)
	key = normalize_key(key)
	if not iv or #iv < 16 then
		iv = ""
		for _ = 1, 16 do
			iv = iv .. string.char(math.random(0, 255))
		end
	end
	local W, nr = aes_expand(key)
	local padded = pkcs7_pad(plain)
	local prev = str2bytes(iv)
	local result = iv
	for i = 1, #padded, 16 do
		local block = str2bytes(padded:sub(i, i + 15))
		for j = 1, 16 do
			block[j] = bxor(block[j], prev[j])
		end
		prev = aes_enc_block(block, W, nr)
		result = result .. bytes2str(prev)
	end
	return result
end

local function aes_cbc_dec(cipher, key, iv_prepended)
	key = normalize_key(key)
	local iv, data
	if iv_prepended ~= false then
		iv = cipher:sub(1, 16)
		data = cipher:sub(17)
	else
		iv = string.rep("\0", 16)
		data = cipher
	end
	local W, nr = aes_expand(key)
	local prev = str2bytes(iv)
	local result = ""
	for i = 1, #data, 16 do
		local block = str2bytes(data:sub(i, i + 15))
		local dec = aes_dec_block(block, W, nr)
		for j = 1, 16 do
			dec[j] = bxor(dec[j], prev[j])
		end
		prev = block
		result = result .. bytes2str(dec)
	end
	return pkcs7_unpad(result)
end

local function pbkdf2(pw, salt, iter, klen)
	iter = iter or 10000
	klen = klen or 32
	local dk = ""
	for i = 1, math.ceil(klen / 32) do
		local u = hmac_sha256(pw, salt .. num2s(i, 4))
		local r = u
		for _ = 2, iter do
			u = hmac_sha256(pw, u)
			local t = {}
			for j = 1, #r do
				t[j] = string.char(bxor(string.byte(r, j), string.byte(u, j)))
			end
			r = table.concat(t)
		end
		dk = dk .. r
	end
	return dk:sub(1, klen)
end

local SynSignal = {}
SynSignal.__index = SynSignal

function SynSignal.new()
	return setmetatable({ _handlers = {}, _waiting = {} }, SynSignal)
end

function SynSignal:Connect(fn)
	assert(type(fn) == "function", "Expected function")
	local conn = { _fn = fn, _signal = self, Connected = true }
	function conn:Disconnect()
		self.Connected = false
		for i, v in ipairs(self._signal._handlers) do
			if v == self then
				table.remove(self._signal._handlers, i)
				break
			end
		end
	end
	table.insert(self._handlers, conn)
	return conn
end

function SynSignal:Once(fn)
	local conn
	conn = self:Connect(function(...)
		conn:Disconnect()
		fn(...)
	end)
	return conn
end

function SynSignal:Wait()
	local t = coroutine.running()
	table.insert(self._waiting, t)
	return coroutine.yield()
end

function SynSignal:Fire(...)
	for _, conn in ipairs(self._handlers) do
		if conn.Connected then
			task.spawn(conn._fn, ...)
		end
	end
	for _, t in ipairs(self._waiting) do
		task.spawn(t, ...)
	end
	self._waiting = {}
end

function SynSignal:DisconnectAll()
	for _, conn in ipairs(self._handlers) do
		conn.Connected = false
	end
	self._handlers = {}
	self._waiting = {}
end

local syn = {}
local _teleportQueue = {}

syn.request = function(params)
	assert(type(params) == "table", "syn.request expects a table")
	assert(type(params.Url) == "string", "syn.request expects Url")
	params.Method = params.Method or "GET"
	local ok, response = pcall(_request, params)
	if not ok then
		error("syn.request failed: " .. tostring(response), 2)
	end
	return {
		Success = response.Success
			or (response.StatusCode and response.StatusCode >= 200 and response.StatusCode < 300)
			or false,
		StatusCode = response.StatusCode or response.Status or 0,
		StatusMessage = response.StatusMessage or response.StatusReason or "",
		Headers = response.Headers or {},
		Cookies = response.Cookies or {},
		Body = response.Body or "",
	}
end

syn.queue_on_teleport = function(script)
	assert(type(script) == "string", "Expected string")
	if _queueteleport then
		return _queueteleport(script)
	end
	table.insert(_teleportQueue, script)
end

syn.clear_teleport_queue = function()
	if genv.clear_teleport_queue then
		return genv.clear_teleport_queue()
	end
	_teleportQueue = {}
end

syn.get_thread_identity = function()
	if _getidentity then
		return _getidentity()
	end
	return 2
end

syn.set_thread_identity = function(id)
	assert(type(id) == "number", "Expected number")
	if _setidentity then
		return _setidentity(id)
	end
end

syn.protect_gui = function(gui)
	assert(typeof(gui) == "Instance", "Expected Instance")
	if _gethui then
		gui.Parent = _gethui()
	else
		gui.Parent = services.CoreGui
	end
end

syn.unprotect_gui = function(gui)
	assert(typeof(gui) == "Instance", "Expected Instance")
	local plr = services.Players.LocalPlayer
	if plr then
		local pg = plr:FindFirstChildWhichIsA("PlayerGui")
		if pg then
			gui.Parent = pg
		end
	end
end

syn.toast_notification = function(options)
	options = options or {}
	pcall(function()
		services.StarterGui:SetCore("SendNotification", {
			Title = options.Title or "Notification",
			Text = options.Content or "",
			Duration = options.Duration or 5,
			Icon = options.Icon or "",
		})
	end)
end

syn.ipc_send = function(data)
	if genv.syn_ipc_send then
		return genv.syn_ipc_send(data)
	end
end

syn.run_on_actor = function(actor, source, ...)
	assert(typeof(actor) == "Instance", "Expected Actor Instance")
	assert(type(source) == "string", "Expected string")
	if _runonactor then
		return _runonactor(actor, source, ...)
	end
	error("run_on_actor requires native support", 2)
end

syn.trampoline_call = function(target, callstack, threadoptions, ...)
	assert(type(target) == "function", "Expected function")
	if genv.trampoline_call then
		return genv.trampoline_call(target, callstack, threadoptions, ...)
	end
	local args = { ... }
	local identity_changed = false
	local old_identity
	if threadoptions then
		if threadoptions.identity and _setidentity and _getidentity then
			old_identity = _getidentity()
			_setidentity(threadoptions.identity)
			identity_changed = true
		end
	end
	local results = { pcall(target, table.unpack(args)) }
	if identity_changed then
		_setidentity(old_identity)
	end
	return table.unpack(results)
end

syn.secure_call = function(fn_or_code, scriptInst, ...)
	local callable
	if type(fn_or_code) == "string" then
		local f, err = loader(fn_or_code)
		if not f then
			error(err, 2)
		end
		callable = f
	elseif type(fn_or_code) == "function" then
		callable = fn_or_code
	else
		error("Expected function or string", 2)
	end
	if typeof(scriptInst) == "Instance" and _getsenv and _clonefunction and _setfenv then
		local cloned = _clonefunction(callable)
		local senv = _getsenv(scriptInst)
		if senv then
			_setfenv(cloned, senv)
		end
		return cloned(...)
	end
	return callable(...)
end

syn.emulate_call = syn.secure_call

syn.write_clipboard = function(content)
	if _clipboard then
		return _clipboard(tostring(content))
	end
end

syn.is_beta = function()
	return false
end

syn.on_actor_state_created = SynSignal.new()

syn.oth = {}

do
	local _oth_hooks = {}
	local _hook_threads = {}
	local _current_hook_info = nil

	syn.oth.hook = function(target, hook)
		assert(type(target) == "function", "Expected function for target")
		assert(type(hook) == "function", "Expected function for hook")

		if not _hookfunction then
			error("hookfunction not available", 2)
		end

		local original_callback
		local hook_entry = {
			target = target,
			hook = hook,
			original = nil,
			active = true,
		}

		local wrapper = _newcclosure(function(...)
			if not hook_entry.active then
				if hook_entry.original then
					return hook_entry.original(...)
				end
				return
			end

			local caller_thread = coroutine.running()
			_hook_threads[caller_thread] = true

			local prev_info = _current_hook_info
			_current_hook_info = {
				original_thread = caller_thread,
				hook_entry = hook_entry,
				is_hook = true,
			}

			local results = { pcall(hook, ...) }

			_current_hook_info = prev_info
			_hook_threads[caller_thread] = nil

			if results[1] then
				return table.unpack(results, 2)
			else
				warn("[syn.oth] Hook error: " .. tostring(results[2]))
			end
		end)

		local old = _hookfunction(target, wrapper)
		hook_entry.original = old
		original_callback = old

		if not _oth_hooks[target] then
			_oth_hooks[target] = {}
		end
		table.insert(_oth_hooks[target], hook_entry)

		return original_callback
	end

	syn.oth.unhook = function(target, hook_or_callback)
		assert(type(target) == "function", "Expected function")
		local hooks = _oth_hooks[target]
		if not hooks or #hooks == 0 then
			return false
		end

		if hook_or_callback then
			for i, entry in ipairs(hooks) do
				if entry.hook == hook_or_callback or entry.original == hook_or_callback then
					entry.active = false
					if _restorefunction and #hooks == 1 then
						pcall(_restorefunction, target)
					end
					table.remove(hooks, i)
					return true
				end
			end
			return false
		else
			if #hooks == 1 then
				hooks[1].active = false
				if _restorefunction then
					pcall(_restorefunction, target)
				end
				_oth_hooks[target] = nil
				return true
			end
			local last = hooks[#hooks]
			last.active = false
			table.remove(hooks)
			return true
		end
	end

	syn.oth.get_root_callback = function()
		if _current_hook_info and _current_hook_info.hook_entry then
			local hooks = _oth_hooks[_current_hook_info.hook_entry.target]
			if hooks and hooks[1] then
				return hooks[1].original
			end
		end
		return nil
	end

	syn.oth.is_hook_thread = function()
		if _current_hook_info then
			return _current_hook_info.is_hook == true
		end
		return false
	end

	syn.oth.get_original_thread = function()
		if _current_hook_info then
			return _current_hook_info.original_thread
		end
		return nil
	end
end

syn.crypt = {}

syn.crypt.encrypt = function(data, key)
	assert(type(data) == "string" and type(key) == "string")
	return b64_encode(aes_cbc_enc(data, key))
end

syn.crypt.decrypt = function(data, key)
	assert(type(data) == "string" and type(key) == "string")
	return aes_cbc_dec(b64_decode(data), key)
end

syn.crypt.hash = function(algorithm, data)
	if data == nil then
		data = algorithm
		algorithm = "sha256"
	end
	assert(type(data) == "string")
	local alg = string.lower(algorithm or "sha256")
	if alg == "sha256" or alg == "sha-256" then
		return sha256_hex(data)
	end
	error("Unsupported hash: " .. tostring(alg) .. " (polyfill: sha256 only)", 2)
end

syn.crypt.random = function(size)
	assert(type(size) == "number" and size >= 0 and size <= 1024)
	local t = {}
	for i = 1, size do
		t[i] = string.char(math.random(0, 255))
	end
	return table.concat(t)
end

syn.crypt.base64 = {
	encode = function(d)
		assert(type(d) == "string")
		return b64_encode(d)
	end,
	decode = function(d)
		assert(type(d) == "string")
		return b64_decode(d)
	end,
}

syn.crypt.hex = {
	encode = function(d)
		assert(type(d) == "string")
		return hex_encode(d)
	end,
	decode = function(d)
		assert(type(d) == "string")
		return hex_decode(d)
	end,
}

syn.crypt.url = {
	encode = function(d)
		assert(type(d) == "string")
		return url_encode(d)
	end,
	decode = function(d)
		assert(type(d) == "string")
		return url_decode(d)
	end,
}

syn.crypt.lz4 = {
	compress = function(d)
		assert(type(d) == "string")
		return num2s(#d, 4) .. d
	end,
	decompress = function(d, size)
		assert(type(d) == "string")
		if size then
			return d:sub(1, size)
		end
		local s = s232num(d, 1)
		return d:sub(5, 4 + s)
	end,
}

syn.crypt.derive = {
	key = function(pw, salt, iter, len)
		assert(type(pw) == "string" and type(salt) == "string")
		return b64_encode(pbkdf2(pw, salt, iter or 10000, len or 32))
	end,
}

syn.crypt.user = {
	sign = function(d)
		assert(type(d) == "string")
		return b64_encode(hmac_sha256("syn_user_key_v3", d))
	end,
	verify = function(d, sig)
		assert(type(d) == "string")
		return b64_encode(hmac_sha256("syn_user_key_v3", d)) == sig
	end,
	prompt = {
		sign = function(d)
			assert(type(d) == "string")
			return b64_encode(hmac_sha256("syn_prompt_key_v3", d))
		end,
		verify = function(d, sig)
			assert(type(d) == "string")
			return b64_encode(hmac_sha256("syn_prompt_key_v3", d)) == sig
		end,
	},
}

syn.crypt.seal = {
	encrypt = function(data, pk)
		assert(type(data) == "string")
		local nonce = syn.crypt.random(24)
		return b64_encode(nonce .. aes_cbc_enc(data, sha256_raw(pk .. nonce)))
	end,
	decrypt = function(data, pk, sk)
		assert(type(data) == "string")
		local raw = b64_decode(data)
		return aes_cbc_dec(raw:sub(25), sha256_raw(pk .. raw:sub(1, 24)))
	end,
}

syn.crypt.sign = {
	keypair = function()
		local sk = syn.crypt.random(32)
		return b64_encode(sha256_raw(sk)), b64_encode(sk)
	end,
	sign = function(data, sk)
		assert(type(data) == "string")
		return b64_encode(hmac_sha256(b64_decode(sk), data) .. data)
	end,
	verify = function(signed, pk)
		assert(type(signed) == "string")
		local raw = b64_decode(signed)
		if #raw <= 32 then
			return nil
		end
		return raw:sub(33)
	end,
	detached = {
		sign = function(data, sk)
			assert(type(data) == "string")
			return b64_encode(hmac_sha256(b64_decode(sk), data))
		end,
		verify = function(data, sig, pk)
			assert(type(data) == "string")
			return b64_encode(hmac_sha256(b64_decode(pk), data)) == sig
		end,
	},
}

syn.crypt.custom = {
	encrypt = function(cipher, data, key, iv)
		assert(type(data) == "string" and type(key) == "string")
		cipher = string.lower(cipher or "aes-cbc")
		if cipher == "aes-cbc" or cipher == "aes-256-cbc" or cipher == "aes" then
			local realiv = iv and b64_decode(iv) or nil
			return b64_encode(aes_cbc_enc(data, key, realiv))
		end
		error("Unsupported cipher: " .. cipher, 2)
	end,
	decrypt = function(cipher, data, key, iv)
		assert(type(data) == "string" and type(key) == "string")
		cipher = string.lower(cipher or "aes-cbc")
		if cipher == "aes-cbc" or cipher == "aes-256-cbc" or cipher == "aes" then
			return aes_cbc_dec(b64_decode(data), key, iv == nil)
		end
		error("Unsupported cipher: " .. cipher, 2)
	end,
	hash = function(alg, data)
		return syn.crypt.hash(alg, data)
	end,
}

syn.websocket = {
	connect = function(url)
		if _WebSocket and _WebSocket.connect then
			return _WebSocket.connect(url)
		end
		error("WebSocket not supported", 2)
	end,
}

genv.syn = syn
genv.SynSignal = SynSignal

genv.getsynasset = genv.getsynasset
	or function(path)
		if genv.getcustomasset then
			return genv.getcustomasset(path)
		end
		return "rbxasset://synapse/" .. tostring(path)
	end

return syn
