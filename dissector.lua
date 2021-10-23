isa_protocol = Proto("ISAmail",  "ISA Project Mail")

message_type = ProtoField.string("message_type", "Message type", base.UNICODE) -- request or response
request = ProtoField.string("request", "Request", base.UNICODE) -- exact request or response
response = ProtoField.string("response", "Server response", base.UNICODE)
message = ProtoField.string("message", "Message", base.UNICODE)
user = ProtoField.string("user", "User", base.UNICODE)
password = ProtoField.string("password", "Encrypted password", base.UNICODE)
token = ProtoField.string("token", "Login token", base.UNICODE)

isa_protocol.fields = { message_type, request, response, message, user, password, token }


function isa_protocol.dissector(buffer, pinfo, tree, offset)
  --len_check(buffer, offset)
  length = buffer:len()
  if length == 0 or length ~= buffer:reported_len() then return end

  pinfo.cols.protocol = isa_protocol.name -- set the protocol name
  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
  -- read all the data
  local info_length = buffer:reported_length_remaining()
  local info_val = buffer(0, info_length):string()

  -- https://stackoverflow.com/questions/24603611/how-to-take-out-only-1-word-from-a-string-in-lua
  local req_res, msg = info_val:match("(%w+)(.+)")

  if req_res == "ok" or req_res == "err" then
    subtree:add(message_type, "response")
    subtree:add(response, req_res)
    local response_table = {}
    for chunk in string.gmatch(msg, '"(.-)"') do 
      table.insert(response_table, chunk) 
    end
    if response_table[1] ~= nil then subtree:add(message, response_table[1]) end
    if response_table[2] ~= nil then subtree:add(token, response_table[2]) end
  else
    subtree:add(message_type, "request")
    subtree:add(request, req_res)
    request_table = {}
      -- https://stackoverflow.com/questions/42206244/lua-find-and-return-string-in-double-quotes
    for chunk in string.gmatch(msg, '"(.-)"') do 
      table.insert(request_table, chunk) 
    end
    if req_res == "register" or req_res == "login" then
      subtree:add(user, request_table[1])
      subtree:add(password, request_table[2])
    else if req_res == "list" or req_res == "logout" then
      subtree:add(token, request_table[1])
    --else if req_res == "fetch" then
    else return 0 -- invalid package - ignore
    end
  end
end
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)