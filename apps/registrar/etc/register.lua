-- auth_id [ expires [ contact node_id interace_id user_agent path ] ]

local id = KEYS[1]
local auth_id = 'a:'..id

-- a:id: (auth_id)(SET)
--   * contact_uri1
--   * contact_uri2
-- c:id:contact_uri1 (expires in TTL)
--   * path: 127.0.0.1:5060

local function get_bindings()
    local ret = {}

    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local expires = redis.call('TTL', contact_key)

        if expires > 0 then
            local hash_data = redis.call('HMGET',contact_key, 'path', 'interface_name', 'node_id', "agent", "headers")
            local d = { c, expires, contact_key, hash_data[1], hash_data[2], hash_data[3], hash_data[4], hash_data[5] }
            ret[#ret+1] = d
        else
            -- cleanup obsolete SET members
            redis.call('SREM',auth_id, c)
        end
    end

    return ret
end

if not ARGV[1] then
    -- no expires. fetch all bindings
    return get_bindings()
end

local expires = tonumber(ARGV[1])

local contact = ARGV[2]

if not expires then
    return 'Wrong expires value'
end

if expires==0 then
    if not contact then
        -- remove all bindings
        for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
            redis.call('DEL', 'c:'..id..':'..c)
        end
        redis.call('DEL', auth_id)
        return nil
    else
        local contact_key = 'c:'..id..':'..contact
        -- remove specific binding
        redis.call('SREM', auth_id, contact)
        redis.call('DEL', contact_key)
        return get_bindings()
    end
end

local contact_key = 'c:'..id..':'..contact
local node_id = ARGV[3]
local interface_name = ARGV[4]
local user_agent = ARGV[5]
local path = ARGV[6]
local headers = ARGV[7]
local bindings_max = tonumber(ARGV[8])

if not user_agent then
    user_agent = ''
end

if not path then
    path = ''
end

-- cleanup obsolete set members
for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
    if 0==redis.call('EXISTS', 'c:'..id..':'..c) then
        redis.call('SREM', auth_id, c)
    end
end

-- check for max allowed bindings
if redis.call('SCARD', auth_id) >= bindings_max then
    return 'Too many registered contacts'
end

-- add binding
redis.call('SADD', auth_id, contact)
redis.call('HMSET', contact_key,
    'node_id', node_id,
    'interface_name', interface_name,
    'agent', user_agent,
    'path', path,
    'headers', headers)

-- set TTL
redis.call('EXPIRE', contact_key, expires)

local bindings = get_bindings()

local _,first_binding = next(bindings)
if first_binding ~= nil then
    -- publish json encoded data in the AoR resolving format to the 'reg' channel
    redis.call('PUBLISH', 'reg', cjson.encode({
        id,
        {
            first_binding[1],
            first_binding[4]
        }
    }))
end

-- return active bindings
return bindings
