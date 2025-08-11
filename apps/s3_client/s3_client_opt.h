#pragma once

#include <confuse.h>

#define PARAM_ACCESS_KEY_NAME  "access_key"
#define PARAM_SECRET_KEY_NAME  "secret_key"
#define PARAM_BUCKET_NAME      "bucket"
#define PARAM_HOST_NAME        "host"
#define PARAM_SECURE_NAME      "secure"
#define PARAM_VERIFY_HOST_NAME "verify_host"
#define PARAM_VERIFY_PEER_NAME "verify_peer"
#define PARAM_VERIFY_ST_NAME   "verify_status"

extern cfg_opt_t s3_client_opt[];
