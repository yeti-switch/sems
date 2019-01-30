#ifndef HTTP_CLIENT_CFG_H
#define HTTP_CLIENT_CFG_H

#include <confuse.h>

#define SECTION_DIST_NAME           "destination"
#define SECTION_ON_SUCCESS_NAME     "on_success"
#define SECTION_ON_FAIL_NAME        "on_failure"

#define PARAM_RESEND_INTERVAL_NAME  "resend_interval"
#define PARAM_RESEND_QUEUE_MAX_NAME "resend_queue_max"
#define PARAM_MODE_NAME             "mode"
#define PARAM_URL_NAME              "urls"
#define PARAM_REQUEUE_LIMIT_NAME    "requeue_limit"
#define PARAM_SUCCESS_CODES_NAME    "succ_codes"
#define PARAM_SUCCESS_ACTION_NAME   "succ_action"
#define PARAM_ACTION_NAME           "action"
#define PARAM_ACTION_ARGS_NAME      "args"
#define PARAM_CONTENT_TYPE_NAME     "content_type"

#define DEFAULT_RESEND_INTERVAL 5000 //milliseconds
#define DEFAULT_RESEND_QUEUE_MAX 10000

#define MODE_PUT_VALUE          "put"
#define MODE_POST_VALUE         "post"
#define ACTION_REMOVE_VALUE     "remove"
#define ACTION_NOTHING_VALUE    "nothing"
#define ACTION_MOVE_VALUE       "move"
#define ACTION_REQUEUE_VALUE    "requeue"

#define ACTION_SUCCESS_TITLE    "success"
#define ACTION_FAIL_TITLE       "fail"

extern cfg_opt_t http_client_opt[];

#endif/*HTTP_CLIENT_CFG_H*/
