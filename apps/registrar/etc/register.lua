-- auth_id [ expires [ contact instance reg_id node_id interace_name user_agent path headers ] ]

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

local function cleanup_instance_reg_id(id, instance, reg_id, one_contact_per_aor)
    local auth_id = 'a:'..id
    for i,c in ipairs(redis.call('SMEMBERS', auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local hash_data = redis.call('HMGET',contact_key, 'instance', 'reg_id')

        if (one_contact_per_aor > 0 or #instance > 0) and hash_data[1] == instance and hash_data[2] == reg_id then
            redis.call('SREM', auth_id, c)
            redis.call('DEL', contact_key)
        end
    end
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
local instance = ARGV[3]
local reg_id = ARGV[4]
local node_id = ARGV[5]
local interface_name = ARGV[6]
local user_agent = ARGV[7]
local path = ARGV[8]
local headers = ARGV[9]
local bindings_max = tonumber(ARGV[10])
local one_contact_per_aor = tonumber(ARGV[11])
local conn_id = 0

-- fetch 'x_register.conn_id'
if type(headers) == 'string' then
    local hdrs = cjson.decode(headers)
    if type(hdrs) == 'table' then
        local x_register_str = hdrs['x_register']
        if type(x_register_str) == 'string' then
            local  x_register = cjson.decode(x_register_str) or {}
            conn_id = x_register['conn_id'] or 0
        end
    end
end

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

cleanup_instance_reg_id(id, instance, reg_id, one_contact_per_aor)

-- check for max allowed bindings
if redis.call('SCARD', auth_id) >= bindings_max then
    return 'Too many registered contacts'
end

-- add binding
redis.call('SADD', auth_id, contact)
redis.call('HMSET', contact_key,
    'conn_id', conn_id,
    'instance', instance,
    'reg_id', reg_id,
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
            first_binding[1], -- contact
            first_binding[7], -- path
            first_binding[8], -- interface_name
        }
    }))
end

-- return active bindings
return bindings
