#pragma once

#include <confuse.h>

#define SECTION_DEST_NAME           "destination"
#define SECTION_ON_SUCCESS_NAME     "on_success"
#define SECTION_ON_FAIL_NAME        "on_failure"

#define PARAM_RESEND_INTERVAL_NAME   "resend_interval"

#define PARAM_RESEND_QUEUE_MAX_NAME         "resend_queue_max"
#define PARAM_RESEND_CONNECTION_LIMIT_NAME  "resend_connection_limit"
#define PARAM_CONNECTION_LIMIT_NAME         "connection_limit"

#define SECTION_AUTH_NAME           "auth"
#define PARAM_AUTH_TYPE             "type"
#define AUTH_TYPE_FB_OA2_VALUE      "firebase_oauth2"
#define AUTH_TYPE_S3_VALUE          "s3"
#define PARAM_AUTH_PRIVATE_KEY      "private_key"
#define PARAM_AUTH_JWT_KIT          "jwt_kid"
#define PARAM_AUTH_JWT_ISS          "jwt_iss"
#define PARAM_AUTH_TOKEN_LIFETIME   "token_lifetime"
#define PARAM_AUTH_ACCESS_KEY       "access_key"
#define PARAM_AUTH_SECRET_KEY       "secret_key"

#define PARAM_MODE_NAME             "mode"
#define PARAM_AUTH_NAME             "auth"
#define PARAM_AUTH_USRPWD           "usrpwd"
#define PARAM_HTTP2_TLS             "http2_tls"
#define PARAM_CERT                  "certificate"
#define PARAM_CERT_KEY              "certificate_key"
#define PARAM_HEADER                "header"
#define PARAM_URL_NAME              "urls"
#define PARAM_SOURCE_ADDRESS_NAME   "source_address"
#define PARAM_REQUEUE_LIMIT_NAME    "requeue_limit"
#define PARAM_SUCCESS_CODES_NAME    "succ_codes"
#define PARAM_SUCCESS_ACTION_NAME   "succ_action"
#define PARAM_ACTION_NAME           "action"
#define PARAM_ACTION_ARGS_NAME      "args"
#define PARAM_CONTENT_TYPE_NAME     "content_type"
#define PARAM_MIN_FILE_SIZE_NAME    "min_file_size"
#define PARAM_MAX_REPLY_SIZE_NAME   "max_reply_size"

#define MODE_PUT_VALUE          "put"
#define MODE_POST_VALUE         "post"
#define MODE_GET_VALUE          "get"

#define ACTION_REMOVE_VALUE     "remove"
#define ACTION_NOTHING_VALUE    "nothing"
#define ACTION_MOVE_VALUE       "move"
#define ACTION_REQUEUE_VALUE    "requeue"
#define ACTION_AUTH_REFRESH     "auth_refresh"

extern cfg_opt_t http_client_opt[];
