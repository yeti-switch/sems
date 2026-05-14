-- auth_id conn_id

local id = ARGV[1]
local auth_id = 'a:'..id
local conid = tonumber(ARGV[2])


local function get_bindings()
    local ret = {}

    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local expires = redis.call('TTL', contact_key)

        if expires > 0 then
            local hash_data = redis.call('HMGET',contact_key, 'instance', 'reg_id', 'node_id', 'path', 'interface_name', 'agent', 'headers', 'conn_id')
            local d = { c, expires, contact_key, hash_data[1], hash_data[2], hash_data[3], hash_data[4], hash_data[5], hash_data[6], hash_data[7], hash_data[8]}
            ret[#ret+1] = d
        else
            -- cleanup obsolete SET members
            redis.call('SREM',auth_id, c)
        end
    end

    return ret
end


for i,c in ipairs(redis.call('SMEMBERS', auth_id)) do
    local contact_key = 'c:'..id..':'..c
    local hash_data = redis.call('HMGET',contact_key, 'conn_id')
    local conn_id = tonumber(hash_data[1])

    if (conn_id > 0 and conn_id == conid) then
        redis.call('SREM', auth_id, c)
        redis.call('DEL', contact_key)
    end
end

-- return get_bindings(id, auth_id, true) ???
