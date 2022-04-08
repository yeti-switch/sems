#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON_ex.h>


cJSON   *cJSON_load(const char *filename)
{
    cJSON *parsed = NULL;
    FILE *file = NULL;
    long length = 0;
    char *content = NULL;
    size_t read_chars = 0;

    /* open in read binary mode */
    file = fopen(filename, "rb");
    if (file == NULL)
        goto cleanup;

    /* get the length */
    if (fseek(file, 0, SEEK_END) != 0)
        goto cleanup;

    length = ftell(file);
    if (length < 0)
        goto cleanup;

    if (fseek(file, 0, SEEK_SET) != 0)
        goto cleanup;

    /* allocate content buffer */
    content = (char*)malloc((size_t)length + sizeof(""));
    if (content == NULL)
        goto cleanup;

    /* read the file into memory */
    read_chars = fread(content, sizeof(char), (size_t)length, file);
    if ((long)read_chars != length) {
        free(content);
        content = NULL;
        goto cleanup;
    }
    content[read_chars] = '\0';

cleanup:
    if (file != NULL)
        fclose(file);

    if (content != NULL) {
        parsed = cJSON_Parse(content);
        free(content);
    }

    return parsed;
}


bool cJSON_save(const char *filename, cJSON *j)
{
    FILE    *file = NULL;
    //char    *content = cJSON_PrintUnformatted(j);
    char    *content = cJSON_Print(j);
    size_t  content_length = content ? strlen(content) : 0,
            write_chars = 0;

    if (content == NULL)
        goto cleanup;

    /* open in write binary mode */
    file = fopen(filename, "wb");
    if (file == NULL)
        goto cleanup;

    /* write the memory  into file */
    write_chars = fwrite(content, sizeof(char), content_length, file);

cleanup:
    if (content)
        free(content);

    if (file != NULL)
        fclose(file);

    return content_length == write_chars;
}


bool cJSON_GetBool(cJSON *item, bool *res)
{
    if (item && (item->type & (cJSON_True | cJSON_False))) {
        *res = !!(item->type&cJSON_True);
        return true;
    }
    return false;
}


bool cJSON_GetDouble(cJSON *item, double *res)
{
    if (item && (item->type & 0xFF) == cJSON_Number) {
        *res = item->valuedouble;
        return true;
    }
    return false;
}


bool cJSON_GetLong(cJSON *item, long *res)
{
    if (item) {
        switch(item->type & 0xFF) {
        case cJSON_Number:
                            *res = item->valuedouble;
                            return true;
        case cJSON_String:
                            *res = atol(item->valuestring);
                            return true;
        }
    }
    return false;
}

bool cJSON_GetLongBase(cJSON *item, long *res, int base)
{
    if (item) {
        switch(item->type & 0xFF) {
        case cJSON_Number:
                            *res = item->valuedouble;
                            return true;
        case cJSON_String:
                            *res = strtol(item->valuestring, NULL, base);
                            return true;
        }
    }
    return false;
}

bool cJSON_GetUInt(cJSON *item, unsigned int *res)
{
    if (item && (item->type & 0xFF) == cJSON_Number) {
        *res = item->valuedouble;
        return *res == item->valuedouble;
    }
    return false;
}


bool cJSON_GetInt(cJSON *item, int *res)
{
    if (item) {
        switch(item->type & 0xFF) {
        case cJSON_Number:
                            *res = item->valueint;
                            return true;
        case cJSON_String:
                            *res = atoi(item->valuestring);
                            return true;
        }
    }
    return false;
}


bool cJSON_GetString(cJSON *item, char **res)
{
    if (item && (item->type & 0xFF) ==  cJSON_String) {
        *res = item->valuestring;
        return true;
    }
    return false;
}


void cJSON_UpsertObject(cJSON *object, const char *key, cJSON *item)
{
    if (cJSON_HasObjectItem(object,key))
        cJSON_ReplaceItemInObject(object, key, item);
    else
        cJSON_AddItemToObject(object, key, item);
}


/** All references to keys must be available while JSON object is live */
void cJSON_UpsertObjectCS(cJSON *object, const char *key, cJSON *item)
{
    if (cJSON_HasObjectItem(object,key))
        cJSON_ReplaceItemInObjectCS(object, key, item);
    else
        cJSON_AddItemToObjectCS(object, key, item);
}


void   cJSON_ReplaceItemInObjectCS(cJSON *object,const char *string,cJSON *newitem)
{
    int     i=0;
    cJSON   *c=object->child;

    while (c && strcasecmp(c->string,string))
    // while(c && cJSON_strcasecmp(c->string,string))
        i++,c=c->next;

    if (c) {
        newitem->string=(char*)string;
        newitem->type |= cJSON_StringIsConst;
        cJSON_ReplaceItemInArray(object,i,newitem);
    }
}


cJSON *cJSON_MergeObject(cJSON *dst, cJSON *src)
{
    if (!cJSON_IsObject(dst) || !cJSON_IsObject(src))
        return dst;

    cJSON   *j = src;

    j = j->child;

    while (j) {
        cJSON_UpsertObject(dst, j->string, cJSON_Duplicate(j,1));
        j = j->next;
    }

    return dst;
}
