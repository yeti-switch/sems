mixer = Proto("mixer","mixer")

mixer.fields = {}
local fds = mixer.fields
fds.stream_id = ProtoField.uint64("mixer.id","id",base.DEC)
fds.rate = ProtoField.int32("mixer.rate","rate",base.DEC)
fds.len = ProtoField.int32("mixer.len","len",base.DEC)
fds.payload= ProtoField.bytes("mixer.payload","payload")

function mixer.dissector(buf, pinfo, tree)
	pinfo.cols.protocol = "mixer"

	local payload_len = buf:reported_length_remaining()	

	local t = tree:add(mixer,buf())
	t:add_le(mixer.fields.stream_id,buf(0,8))
	t:add_le(mixer.fields.rate,buf(8,4))
	t:add_le(mixer.fields.len,buf(12,4))
	t:add_le(mixer.fields.payload,buf(16))
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(5002,mixer)
