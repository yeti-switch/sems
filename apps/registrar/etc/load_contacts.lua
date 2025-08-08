local data = {}
local r = { 0 }
local e, other
repeat
    r = redis.call('SCAN', r[1], 'MATCH', 'c:*')
    for k,v in pairs(r[2]) do
        e = redis.call('HMGET',v,'node_id','path','interface_name')
        table.insert(e, v)
        other = redis.call('HMGET',v,'agent','headers')
        for _, value in ipairs(other) do
            table.insert(e, value)
        end
        data[#data +1] = e
    end
until(tonumber(r[1]) == 0)

return data
