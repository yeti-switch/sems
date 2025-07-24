-- KEYS: auth_id list

local ret = {}

for i,id in ipairs(KEYS) do
    local cset = { }
    local auth_id = 'a:'..id
    for j,c in ipairs(redis.call('SMEMBERS',auth_id)) do
        local contact_key = 'c:'..id..':'..c
        if 1==redis.call('EXISTS', contact_key) then
            cset[#cset + 1] = c
            cset[#cset + 1] = redis.call('HGET',contact_key,'path')
            cset[#cset + 1] = redis.call('HGET',contact_key,'interface_name')
        end
    end

    if next(cset) ~= nil then
        ret[#ret + 1] = id
        ret[#ret + 1] = cset
    end
end

return ret
