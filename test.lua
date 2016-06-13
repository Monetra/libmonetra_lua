local libmonetra = require("libmonetra")

local host = "testbox.monetra.com"
local port = 8665
local user = "test_ecomm:public"
local pass = "publ1ct3st"
local method = libmonetra.CONN_SSL
local cafile = nil
local verifyssl = false
local ret = nil
local err = nil
local tran = nil

local conn = libmonetra.Monetra(host, port, method)

if verifssl then
	if cafile then
		ret, err = conn:SetSSL_CAfile(cafile)
		if not ret then
			print(err)
			return
		end
	end
	conn:VerifySSLCert(true)
end

-- Set to blocking mode, means we do not have to
-- do a Monitor() loop. TransSend() will do this for us.
conn:SetBlocking(true)

-- Set a timeout to be appended to each transaction
-- sent to Monetra.
conn:SetTimeout(30)

print("Connectiong to " .. host .. ":" .. port .. "using method " .. (method == libmonetra.CONN_IP and "IP" or (method == libmonetra.CONN_SSL and "SSL" or "Unknown")))

ret, err = conn:Connect()
if not ret then
	print("connect fail: " .. err)
	return
end
print("Connected")

tran = conn:TransNew()
if not tran then
	print("Could not create transaction")
	conn:Disconnect()
	return
end

conn:TransKeyVal(tran, "username", user)
conn:TransKeyVal(tran, "password", pass)
conn:TransKeyVal(tran, "action", "admin")
conn:TransKeyVal(tran, "admin", "gut")

print("Sending Unsettled report request...")

ret, err = conn:TransSend(tran)
if not ret then
	print("Communication error: " .. err)
	conn:Disconnect()
	return
end
print("Response received")

-- We do not have to perform the Monitor() loop
-- because we are in blocking mode.
if conn:ReturnStatus(tran) ~= libmonetra.SUCCESS then
	print("Audit failed")
	conn:Disconnect()
	return
end

if not conn:IsCommaDelimited(tran) then
	print("Not a comma delimited response!")
	conn:Disconnect()
	return
end

-- Print the raw, unparsed data.
--print("Raw Data: " .. conn:GetCommaDelimited(tran))

-- Tell the API to parse the Data.
if not conn:ParseCommaDelimited(tran) then
	print("Parsing comma delimited data failed!")
	conn:Disconnect()
	return
end

-- Retrieve each number of rows/columns.
local rows = conn:NumRows(tran)
local cols = conn:NumColumns(tran)

-- Print all the headers separated by |'s.
local headers = {}
for i=1,cols do
	table.insert(headers, conn:GetHeader(tran, i))
end
print(table.concat(headers, "|"))

-- Print one row per line, each cell separated by |'s.
for i=1,rows do
	local row = {}
	for j=1,cols do
		table.insert(row, conn:GetCellByNum(tran, j, i))
	end
	print(table.concat(row, "|"))
end

conn:DeleteTrans(tran)
conn:Disconnect()
conn = nil

