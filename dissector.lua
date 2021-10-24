isa_protocol = Proto("ISAmail",  "ISA Project Mail")

req_res_match = {}
-- https://ask.wireshark.org/question/15238/how-to-get-current-frame-number-or-stream-number-in-lua-plugin/
local stream_index = Field.new("tcp.stream")
local get_matching_request, set_matching_request, reassembly

message_type = ProtoField.string("message_type", "Message type", base.UNICODE) -- request or response
request = ProtoField.string("request", "Request", base.UNICODE) -- exact request or response
response = ProtoField.string("response", "Server response", base.UNICODE)
message = ProtoField.string("message", "Message", base.UNICODE)

user = ProtoField.string("user", "User", base.UNICODE)
password = ProtoField.string("password", "Encrypted password", base.UNICODE)
token = ProtoField.string("token", "Login token", base.UNICODE)
recipient = ProtoField.string("recipient", "Recipient", base.UNICODE)
sender = ProtoField.string("sender", "Sender", base.UNICODE)
subject = ProtoField.string("subject", "Subject", base.UNICODE)
body = ProtoField.string("body", "Message body", base.UNICODE)
msg_id = ProtoField.string("msg_id", "Message ID", base.uint16)
msg_count = ProtoField.string("msg_count", "Message count", base.uint16)

isa_protocol.fields = { message_type, request, response, message, user, password, token, recipient, sender, subject, body, msg_id, msg_count }

function isa_protocol.dissector(buffer, pinfo, tree, offset)
  length = buffer:len()
  if length == 0 or length ~= buffer:reported_len() then return end

  local stream_idx_ex = stream_index()

  pinfo.cols.protocol = isa_protocol.name -- set the protocol name
  local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Data")
  -- read all the data
  local info_length = buffer:reported_length_remaining()
  local info_val = buffer(0, info_length):string()

  -- https://stackoverflow.com/questions/24603611/how-to-take-out-only-1-word-from-a-string-in-lua
  local req_res, msg = info_val:match("(%w+)(.+)")

    --* reassemble long messages (several packets)
    pinfo.desegment_len = reassembly(buffer, info_length, req_res)

  --* packet is server response
  --* ERR
  if req_res == "err" then
    prev_req = get_matching_request(stream_idx_ex.value)
    subtree:add(message_type, "response")
    subtree:add(request, prev_req)
    subtree:add(response, "error")
    local err_msg = string.match(msg, '"(.-)"')
    if err_msg ~= nil then subtree:add(message, err_msg) end

  --* OK
  elseif req_res == "ok" then
    prev_req = get_matching_request(stream_idx_ex.value)
    subtree:add(message_type, "response")
    subtree:add(request, prev_req)
    subtree:add(response, "ok")

    --* parse double-quoted expressions and insert into table
    local response_table = {}
    for chunk in string.gmatch(msg, '"(.-)"') do 
      table.insert(response_table, chunk) 
    end

    --* insert into the subtree according to the request
    if prev_req == "register" or prev_req == "send" or prev_req == "logout" then
      subtree:add(message, response_table[1])
    elseif prev_req == "login" then
      subtree:add(message, response_table[1])
      subtree:add(token, response_table[2])
    elseif prev_req == "list" then
      local msg_listed = select(2, string.gsub(msg, "%(%d+", ""))
      subtree:add(msg_count, msg_listed)
    elseif prev_req == "fetch" then
      subtree:add(sender, response_table[1])
      subtree:add(subject, response_table[2])
      subtree:add(body, response_table[3])
    --* invalid package - ignore
    else return
    end

  --* packet is client request
  else
    local stream_idx_ex = stream_index()
    subtree:add(message_type, "request")
    subtree:add(request, req_res)
        
    --* parse double-quoted expressions and insert into table
    -- https://stackoverflow.com/questions/42206244/lua-find-and-return-string-in-double-quotes
    request_table = {}
    for chunk in string.gmatch(msg, '"(.-)"') do 
      table.insert(request_table, chunk) 
    end

    --* insert into the subtree according to the request
    if req_res == "register" or req_res == "login" then
      subtree:add(user, request_table[1])
      subtree:add(password, request_table[2])
    elseif req_res == "list" or req_res == "logout" then
      subtree:add(token, request_table[1])
    elseif req_res == "send" then
      subtree:add(token, request_table[1])
      subtree:add(recipient, request_table[2])
      subtree:add(subject, request_table[3])
      subtree:add(body, request_table[4])
    elseif req_res == "fetch" then
      subtree:add(token, request_table[1])
      subtree:add(msg_id, string.match(msg, "(%d+)%)"))
    --* invalid package - ignore
    else return
    end
  end

  --* set request name of the current packet stream
  set_matching_request(stream_idx_ex.value, req_res)

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(32323, isa_protocol)

function reassembly(buffer, len, current_request)
  local ending_char = buffer(len-1, 1):string()
  local ending_chars = buffer(len-2, 2):string()
  if ending_chars ~= '")' and ending_chars ~= "))" then
    if current_request == "fetch" and ending_char == ")" then return 0 end
    return DESEGMENT_ONE_MORE_SEGMENT
  end
  return 0
end

--- Set the request name according to the stream index.
-- @param stream_index_num number: stream index.
function set_matching_request(stream_index_num, val)
  if req_res_match[stream_index_num] == nil then
    req_res_match[stream_index_num] = val
  end
  return
end

--- Get the request name according to the stream index.
-- @param stream_index_num number: stream index.
-- @return string: request name,
-- or "unknown" if request was not found.
function get_matching_request(stream_index_num)
  if req_res_match[stream_index_num] ~= nil then
    return req_res_match[stream_index_num]
  else
    return "unknown"
  end
end
