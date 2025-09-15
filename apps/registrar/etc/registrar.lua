#!lua name=registrar

-- a:id: (auth_id)(SET)
--   * contact_uri1
--   * contact_uri2
-- c:id:contact_uri1 (expires in TTL)
--   * path: 127.0.0.1:5060
local function get_bindings(id, auth_id, cleanup)
    local ret = {}

    for i,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        local expires = redis.call('TTL', contact_key)
        if expires > 0 then
            local hash_data = redis.call('HMGET',contact_key, 'instance', 'reg_id', 'node_id', 'path', 'interface_name', 'agent', 'headers', 'conn_id')
            local d = { c, expires, contact_key, hash_data[1], hash_data[2], hash_data[3], hash_data[4], hash_data[5], hash_data[6], hash_data[7], hash_data[8]}
            ret[#ret+1] = d
        elseif cleanup then
            -- cleanup obsolete SET members
            redis.call('SREM',auth_id, c)
        end
    end

    return ret
end

local function load_contacts()
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
            table.insert(e, redis.call('TTL', v))
            data[#data +1] = e
        end
    until(tonumber(r[1]) == 0)

    return data
end

-- keys: auth_id list
local function aor_lookup(keys)
    local ret = {}

    for i,id in ipairs(keys) do
        local cset = { }
        local auth_id = 'a:'..id
        for j,c in ipairs(redis.call('SMEMBERS',auth_id)) do
            local contact_key = 'c:'..id..':'..c
            if 1==redis.call('EXISTS', contact_key) then
                cset[#cset + 1] = c
                cset[#cset + 1] = redis.call('HGET',contact_key,'path')
            end
        end

        if next(cset) ~= nil then
            ret[#ret + 1] = id
            ret[#ret + 1] = cset
        end
    end

    return ret
end

local function rpc_aor_lookup(keys)
    local ret = {}
    local aor_keys = {}

    if next(keys) == nil then
        local r = { 0 }
        repeat
            r = redis.call('SCAN', r[1], 'MATCH', 'a*')
            for k,v in pairs(r[2]) do
                aor_keys[string.sub(v,3)] = 1
            end
        until(r[1] == '0')
    else
        for k,v in ipairs(keys) do aor_keys[v] = 1 end
    end

    for id in pairs(aor_keys) do
        ret[#ret + 1] = id
        ret[#ret + 1] = get_bindings(id, 'a:'..id, false)
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

local function transport_down(keys, args)
    local id = args[1]
    local auth_id = 'a:'..id
    local conid = tonumber(args[2])

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
end


-- auth_id [ expires [ conn_id [ contact instance reg_id node_id interace_name user_agent path headers ] ] ]
local function register(keys, args)
    local id = keys[1]
    local auth_id = 'a:'..id

    if not args[1] then
        -- no expires. fetch all bindings
        return get_bindings(id, auth_id, true)
    end

    local expires = tonumber(args[1])
    local contact = args[2]

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
            return get_bindings(id, auth_id, true)
        end
    end

    local contact_key = 'c:'..id..':'..contact
    local instance = args[3]
    local reg_id = args[4]
    local node_id = args[5]
    local interface_name = args[6]
    local user_agent = args[7]
    local path = args[8]
    local headers = args[9]
    local bindings_max = tonumber(args[10])
    local one_contact_per_aor = tonumber(args[11])
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
        'node_id',node_id,
        'interface_name',interface_name,
        'agent',user_agent,
        'path',path,
        'headers', headers)

    -- set TTL
    redis.call('EXPIRE', contact_key, expires)

    local bindings = get_bindings(id, auth_id, true)

    local _,first_binding = next(bindings)
    if first_binding ~= nil then
        -- contact[1] expires[2] contact_key[3] instance [4] reg_id[5] node_id[6] path[7] interface_name[8] agent[9] headers[10] conn_id[11]
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
end


redis.register_function{function_name="register",      callback=register}
redis.register_function{function_name="transport_down",callback=transport_down}
redis.register_function{function_name="load_contacts", callback=load_contacts, flags={"no-writes"}}
redis.register_function{function_name="aor_lookup",    callback=aor_lookup,    flags={"no-writes"}}
redis.register_function{function_name="rpc_aor_lookup",callback=rpc_aor_lookup,flags={"no-writes"}}
