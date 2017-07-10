# destinations=<comma-separated destinations list>
#
# Default: empty
#
# destinations=pcap

# resend_interval=<msec>
#
# interval between resend attempts for all destinations with failed_upload action 'requeue'
#
# Default: 5000
#
# resend_interval=5000

# resend_queue_max=<integer>
#
# maximum events queue size for all requeued uploads
# set 0 for unlimited
#
# Default: 10000
#
# resend_queue_max=10000

# <destination>_mode=<modes>
#
# available modes: put, post
#
# Default: mandatory
#
# pcap_mode=put

# <destination>_upload_url=<url[,url2...]>
#
# comma-spearated list of URLs
# automatic failover if specified more than one url
#
# Default: mandatory
#
# pcap_url=http://127.0.0.1/upload

# <destination>_succ_codes=<mask[,mask2...]>
#
# comma-spearated list of the masks
# for codes to be considered as successfull
#
# Default: 2xx
#
# pcap_succ_codes=2xx

# <destination>_succ_action=<action>
#
# available actions: remove, move, nothing
#
# Default: remove
#
# pcap_succ_action=remove

# <destination>_succ_action_arg=<arg>
#
# meaning depends from choosen post-upload action
#
# Default: mandatory for 'move' post-upload action
#
# pcap_succ_action_arg=/tmp

# <destination>_fail_action=<action>
#
# available actions: remove, move, nothing, requeue
#
# Default: nothing
#
# pcap_fail_action=nothing

# <destination>_requeue_limit=<integer>
#
# Limit of the attempts for requeue fail action
# unlimited if zero
#
# Default: 0
#
# pcap_requeue_limit=0

# <destination>_fail_action_arg=<arg>
#
# meaning depends from choosen failed-upload action
#
# Default: mandatory for 'move' failed-upload action
#
# pcap_fail_action_arg=/tmp

# <destination>_content_type=<mimetype>
#
# supported only in 'post' mode
# specifies custom Content-Type http header value
#
# Example value: application/vnd.api+json
# Default: empty
#
