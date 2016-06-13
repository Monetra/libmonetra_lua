--[[
Copyright 2012 Main Street Softworks, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY MAIN STREET SOFTWORKS INC ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MAIN STREET SOFTWORKS INC OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the
authors and should not be interpreted as representing official policies, either expressed
or implied, of Main Street Softworks, Inc.
]]--

local socket = require("socket")
local mime   = require("mime")
local ssl    = require("ssl")

local M = {}
local Monetra = {}
local Monetra_priv = setmetatable({}, {__index = Monetra})
local Monetra_mt = { __metatable = {}, __index = Monetra_priv }

local VERSION        = "0.9.6"

local CONN_SSL       = 1
local CONN_IP        = 2

local TRAN_STATUS_NEW  = 1
local TRAN_STATUS_SENT = 2
local TRAN_STATUS_DONE = 3

local ERROR          = -1
local FAIL           = 0
local SUCCESS        = 1

local DONE           = 2
local PENDING        = 3

M.VERSION = VERSION
M.CONN_SSL = CONN_SSL
M.CONN_IP  = CONN_IP
M.ERROR  = ERROR
M.FAIL   = FAIL
M.SUCCESS = SUCCESS
M.DONE    = DONE
M.PENDING = PENDING

local function verify_comma_delimited(data)
	for c in data:gmatch(".") do
		if c == "\n" or c == "\r" or c == "," then
			return true
		end
		if c == "=" then
			return false
		end
	end

	-- Should never get here
	return false
end

local function explode_quoted(delim, data, quote_char, max_sects)
	local parts = {}
	local count = 0
	local on_quote = false
	local beginsect = 1
	local ignore = 0

	for i=1, #data do
		if i > ignore and data:sub(i, i) == quote_char then
			-- Double quote char acts as escaping
			if data:sub(i+1, i+1) == quote_char then
				ignore = i + 1 
			elseif on_quote then
				on_quote = false
			else
				on_quote = true
			end
		end
		if i > ignore and data:sub(i, i) == delim and not on_quote then
			table.insert(parts, data:sub(beginsect, i - 1))
			beginsect = i + 1
			count = count + 1
			if max_sects ~= 0 and count == max_sects - 1 then
				break
			end
		end
	end

	if beginsect <= #data then
		table.insert(parts, data:sub(beginsect, #data))
	end
	return parts
end

local function remove_dupe_quotes(s)
	local n, _ = s:gsub('""', '"')
	return n
end

local function trim(s)
	return s:match'^()%s*$' and '' or s:match'^%s*(.*%S)'
end

local function parsecsv(data, delimiter, enclosure)
	if not delimiter then
		delimiter = ","
	end
	if not enclosure then
		enclosure = '"'
	end

	local csv = {}
	local lines = explode_quoted("\n", data, enclosure, 0)
	for i,n in ipairs(lines) do
		local row = {}
		local cells = explode_quoted(delimiter, n, enclosure, 0)
		for j,m in ipairs(cells) do
			table.insert(row, remove_dupe_quotes(trim(m)))
		end
		table.insert(csv, row) 
	end

	return csv
end

local function b64(s)
	local enc = mime.b64(s)
	return enc
end

local function unb64(s)
	local dec = mime.unb64(s)
	return dec
end

---

function Monetra_priv:findtranbyid(tid)
	if not self.trandb or not self.trandb[tid] then
		return nil
	end

	return self.trandb[tid]
end

function Monetra_priv:verifyping()
	local max_ping_time = 5;
	local blocking = self.blocking

	self:SetBlocking(false)

	tid = self:TransNew()
	self:TransKeyVal(tid, "action", "ping")
	if not self:TransSend(tid) then
		self:DeleteTrans(tid)
		return false
	end

	local lasttime = os.time()
	while self:CheckStatus(tid) == PENDING and os.time() - lasttime <= max_ping_time do
		local wait_time_ms = (max_ping_time - (os.time() - lasttime)) * 1000
		if wait_time_ms < 0 then
			wait_time_ms = 0
		elseif wait_time_ms > max_ping_time * 1000 then
			wait_time_ms = max_ping_time * 1000
		end

		if not self:Monitor(wait_time_ms) then
			break
		end
	end

	self:SetBlocking(blocking)
	status = self:CheckStatus(tid)
	self:DeleteTrans(tid)

	if status ~= DONE then
		return false
	end
	return true
end

--

function Monetra:new(host, port, method)
	local o = setmetatable({}, Monetra_mt)

	o.host = host
	o.port = port
	o.method = method

	o.next_tid = 1
	o.trandb = {}

	o.timeout_conn = 0.01 -- seconds
	o.timeout_tran = 0

	o.readbuf = ""
	o.writebuf = ""

	return o
end
-- Allows Monetra to be initialized with Monetra(...) or Monetra:new(...)
setmetatable(Monetra, { __call = Monetra.new })

function Monetra:Connect()
	local tcp_s = nil
	local ssl_s = nil
	local ret   = nil
	local err   = nil
	local params

	if self.sock then
		self:Disconnect()
	end

	if self.method ~= CONN_SSL and self.method ~= CONN_IP then
		return nil, "Unknown connection method requested"
	end

	tcp_s = socket.tcp()
	ret, err = tcp_s:connect(self.host, self.port)

	if not ret then
		return nil, err
	end

	tcp_s:settimeout(self.timeout_conn)
	self.sock = tcp_s
	self.sock_tcp = tcp_s

	if self.method == CONN_SSL then
		params = {
			mode="client",
			protocol="tlsv1"
		}
		if self.ssl_cafile then
			params.cafile = self.ssl_cafile
		end
		if self.ssl_key then
			params.key = self.ssl_key
		end
		if self.ssl_cert then
			params.certificate = self.ssl_cert
		end
		if self.verify_ssl then
			params.verify = "peer"
		end

		ssl_s = ssl.wrap(tcp_s, params)
		ret, err = ssl_s:dohandshake()

		if not ret then
			self:Disconnect()
			return nil, err
		end

		ssl_s:settimeout(self.timeout_conn)
		self.sock = ssl_s
		self.sock_ssl = ssl_s
	end

	if self.verify_conn and not self:verifyping() then
		self:Disconnect()
		return nil, "PING request failed"
	end

	return true
end

function Monetra:Disconnect()
	if self.sock_tcp then
		self.sock_tcp:close()
		self.sock_tcp = nil
	end

	if self.sock_ssl then
		self.sock_ssl:close()
		self.sock_ssl = nil
	end

	self.sock = nil
end

function Monetra:SetBlocking(block)
	self.blocking = block
	return true
end

function Monetra:TransNew()
	local tid = self.next_tid
	self.next_tid = self.next_tid + 1

	self.trandb[tid] = {
		tid=tid,
		status=TRAN_STATUS_NEW,
		request={
			fields={}
		}
	}

	return tid
end

function Monetra:MaxConnTimeout(secs)
	self.timeout_conn = secs
	return true
end

function Monetra:ValidateIdentifier(val)
	-- Always validated, stub for compatibility
	return true
end

function Monetra:VerifyConnection(val)
	self.verify_conn = val
	return true
end

function Monetra:VerifySSLCert(val)
	self.verify_ssl = val
	return true
end

function Monetra:SetSSL_CAfile(cafile)
	if not cafile then
		return false
	end

	self.ssl_cafile = cafile	
	return true
end

function Monetra:SetSSL_Files(sslkeyfile, sslcertfile)
	if not sslkeyfile or not sslcertfile then
		return false
	end

	self.ssl_key = sslkeyfile
	self.ssl_cert = sslcertfile
	return true
end

function Monetra:SetTimeout(secs)
	self.timeout_tran = secs;
end

function Monetra:TransKeyVal(tid, key, val)
	local tran = self:findtranbyid(tid)
	if not tran then
		return false
	end

	tran.request.fields[key] = val
	return true
end

function Monetra:TransBinaryVal(tid, key, val)
	return TransKeyVal(tid, key, b64(val))
end

function Monetra:CheckStatus(tid)
	local tran = self:findtranbyid(tid)
	if not tran or not tran.status or (tran.status ~= TRAN_STATUS_SENT and tran.status ~=TRAN_STATUS_DONE) then
		return ERROR
	end

	if tran.status == TRAN_STATUS_SENT then
		return PENDING
	end

	return DONE
end

function Monetra:DeleteTrans(tid)
	if self.trandb[tid] and self.trandb[tid].status ~= TRAN_STATUS_SENT then
		self.trandb[tid] = nil
	end
end

function Monetra:TransInQueue()
	local count = 0
	for k,v in pairs(self.trandb) do
		if v then
			count = count + 1
		end
	end
	return count
end

function Monetra:TransactionsSent()
	if self.writebuf and #self.writebuf > 0 then
		return false
	end

	return true
end

function Monetra:Monitor_write()
	local sent = nil
	local err = nil

	if not self.sock then
		return false, "Not connected: write"
	end

	if self.writebuf and #self.writebuf > 0 then
		sent, err = self.sock:send(self.writebuf)
		if sent == nil then
			return false, err
		elseif sent == #self.writebuf then
			self.writebuf = ""
		else
			self.writebuf = self.writebuf:sub(sent + 1, #self.writebuf)
		end
	end

	return true
end

function Monetra:Monitor_read(timeoutms)
	local data
	local err
	local par

	if not self.sock then
		return false, "Not connected: read"
	end

	-- Reading from the socket twice on purpose.
	--
	-- socket:receive "*a" does not return immediately after reading data.
	-- It will wait until the connection is closed or until timeout.
	-- socket:receive with a number will return as soon as that many
	-- bytes has been read.
	--
	-- We first read 1 byte using the specified timeout. If we have data
	-- we will read again with *a and a timeout of 0. Essentially we are
	-- peeking if there is data and if there is reading it. If we timeout
	-- with the first read we don't do the second because there is no data
	-- at all. This allows us to read all available bytes immediately.
	local rpat = 1
	local timeout = timeoutms / 1000
	for i=1, 2 do
		if i == 2 then
			timeout = 0
			rpat= "*a"
		end

		self.sock:settimeout(timeout)
		data, err, par = self.sock:receive(rpat)

		if not data and not par or par == "" and err ~= "timeout" then
			return false, err
		elseif data then
			self.readbuf = self.readbuf .. data
		elseif par then
			self.readbuf = self.readbuf .. par
		else
			return true
		end
	end

	return true
end

function Monetra:Monitor_parse()
	-- Parse
	while #self.readbuf > 0 do
		if self.readbuf:sub(1, 1) ~= "\2" then
			self:Disconnect()
			return false, "Protocol error, responses must start with STX"
		end
	
		local etx = self.readbuf:find("\3")
		if not etx then
			-- Not enough data
			break
		end

		local i0, i1, tid, raw = self.readbuf:find("\2(%d+)\28([^\3]+)\3")
		self.readbuf = self.readbuf:sub(i1 + 1, #self.readbuf)

		local tran = self:findtranbyid(tonumber(tid))
		if tran then
			tran.response = {
				raw = raw,
				comma_delimited = verify_comma_delimited(raw),
				fields = {}
			}

			if not tran.response.comma_delimited then
				local lines = explode_quoted("\n", raw, '"', 0)
				for i,n in ipairs(lines) do
					local line = trim(n)
					if #line ~= 0 then
						local keyval = explode_quoted("=", line, 0, 2)
						if keyval and #keyval == 2 and keyval[1] and #keyval[1] > 0 then
							tran.response.fields[keyval[1]] = remove_dupe_quotes(trim(keyval[2]))
						end
					end
				end
			end

			tran.status = TRAN_STATUS_DONE
		end
	end

	return true
end

function Monetra:Monitor(timeoutms)
	local ret = nil
	local err = nil

	if not timeoutms then
		timeoutms = -1
	end

	ret, err = self:Monitor_write()
	if not ret then
		return false, err
	end

	ret, err = self:Monitor_read(timeoutms)
	if not ret then
		return false, err
	end

	ret, err = self:Monitor_parse()
	if not ret then
		return false, err
	end

	return true;
end

function Monetra:CompleteAuthorizations()
	local ids = {}
	for k,v in pairs(self.trandb) do
		if v and v.status == TRAN_STATUS_DONE then
			table.insert(ids, k)
		end
	end
	return ids
end

function Monetra:GetCell(tid, col, row)
	local tran = self:findtranbyid(tid)
	row = row + 1

	if not tran then
		return nil 
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response or not tran.response.comma_delimited then
		return nil
	end
	if not tran.response or not tran.response.csv or not tran.response.csv[row] then
		return nil 
	end

	local colnum = tran.response.csv_header_col_map[col:lower()] 
	if colnum then
		return tran.response.csv[row][colnum]
	end

	return nil

end

function Monetra:GetBinaryCell(tid, col, row)
	local out = nil
	row = row + 1
	local cel = self:GetCell(tid, col, row)
	if cel then
		out = unb64(cel)
	end
	return out
end

function Monetra:GetCellByNum(tid, col, row)
	local tran = self:findtranbyid(tid)
	row = row + 1

	if not tran then
		return nil 
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response or not tran.response.comma_delimited then
		return nil
	end
	if not tran.response or not tran.response.csv or not tran.response.csv[row] then
		return nil 
	end

	return tran.response.csv[row][col]
end

function Monetra:GetCommaDelimited(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return nil 
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response then
		return nil
	end

	return tran.response.raw
end

function Monetra:GetHeader(tid, col)
	local tran = self:findtranbyid(tid)
	if not tran then
		return nil 
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response or not tran.response.comma_delimited then
		return nil
	end
	if not tran.response or not tran.response.csv or not tran.response.csv[1] or not tran.response.csv[1][col] then
		return nil 
	end

	return tran.response.csv[1][col]
end

function Monetra:IsCommaDelimited(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return false
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return false
	end
	if not tran.response or not tran.response.comma_delimited then
		return false
	end

	return tran.response.comma_delimited
end

function Monetra:NumColumns(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return 0
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return 0
	end
	if not tran.response or not tran.response.comma_delimited then
		return 0
	end
	if not tran.response or not tran.response.csv or not tran.response.csv[1] then
		return 0
	end

	return #tran.response.csv[1]
end

function Monetra:NumRows(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return 0
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return 0
	end
	if not tran.response or not tran.response.comma_delimited then
		return 0
	end
	if not tran.response or not tran.response.csv or not tran.response.csv then
		return 0
	end

	return #tran.response.csv - 1
end

function Monetra:ResposeKeys(tid)
	local tran = self:findtranbyid(tid)
	local keys = {}

	if not tran then
		return nil
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response or not tran.response.fields then
		return nil
	end

	for k,v in pairs(tran.response.fields) do
		table.insert(keys, k)
	end

	return keys
end

function Monetra:ResponseParam(tid, key)
	local tran = self:findtranbyid(tid)
	if not tran then
		return nil
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return nil
	end
	if not tran.response or not tran.response.fields then
		return nil
	end

	return tran.response.fields[key]
end

function Monetra:ReturnStatus(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return FAIL
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return ERROR
	end

	if tran.response.comma_delimited then
		return SUCCESS
	end

	local code = self:ResponseParam(tid, "code")
	if code and code:lower() == "auth" or code:lower() == "success" then
		return SUCCESS
	end

	return FAIL
end

function Monetra:TransSend(tid)
	local ret = nil
	local err = nil
	local tran = self:findtranbyid(tid)

	if not tran then
		return false, "Unknown transaction id"
	end
	if tran.status ~= TRAN_STATUS_NEW then
		return false, "Transaction has already been sent"
	end

	tran.status = TRAN_STATUS_SENT
	-- Structure Transaction

	-- STX, identifier, FS
	local tran_str = "\2" .. tid .. "\28"

	if tran.request.fields['action'] and tran.request.fields['action']:lower() == "ping" then
		tran_str = tran_str .. "PING"
	else
		for k,v in pairs(tran.request.fields) do
			tran_str = tran_str .. k .. '="' .. tostring(v):gsub('"', '""') .. '"' .. "\r\n"
		end
		if tran.timeout_tran and tran.timeout_tran > 0 then
			tran_str = tran_str .. 'timeout="' .. tran.timeout_tran .. '"\r\n'
		end
	end

	tran_str = tran_str .. "\3"

	self.writebuf = self.writebuf .. tran_str

	if self.blocking then
		while self:CheckStatus(tid) == PENDING do
			ret, err = self:Monitor(-1)
			if not ret then
				return false, err
			end
		end
	end

	return true
end

function Monetra:ParseCommaDelimited(tid)
	local tran = self:findtranbyid(tid)
	if not tran then
		return false 
	end
	if tran.status ~= TRAN_STATUS_DONE then
		return false
	end

	tran.response.csv = parsecsv(tran.response.raw, ",", '"')
	tran.response.csv_header_col_map =  {}
	for i,v in ipairs(tran.response.csv[1]) do
		tran.response.csv_header_col_map[v:lower()] = i
	end

	return true
end

M.Monetra = Monetra

return M

