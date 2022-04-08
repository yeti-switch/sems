#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <cJSON.h>

static __always_inline void cJSON_Auto_Delete(cJSON **j) { cJSON_Delete(*j); }
#define cJSON_auto_t cJSON __attribute__((cleanup(cJSON_Auto_Delete)))

bool    cJSON_save(const char *file, cJSON *j);

cJSON   *cJSON_load(const char *file);

bool    cJSON_GetBool(cJSON *item, bool *res);

bool    cJSON_GetDouble(cJSON *item, double *res);

bool    cJSON_GetLong(cJSON *item, long *res);

bool    cJSON_GetLongBase(cJSON *item, long *res, int base);

bool    cJSON_GetUInt(cJSON *item, unsigned int *res);

bool    cJSON_GetInt(cJSON *item, int *res);

bool    cJSON_GetString(cJSON *item, char **res);

void    cJSON_UpsertObject(cJSON *object, const char *key, cJSON *item);

void    cJSON_UpsertObjectCS(cJSON *object, const char *key, cJSON *item);

void    cJSON_ReplaceItemInObjectCS(cJSON *object,const char *string,cJSON *newitem);

cJSON   *cJSON_MergeObject(cJSON *dst, cJSON *src);
