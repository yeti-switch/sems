#pragma once

/* ----------------------------------
 * See: server/catalog/pg_type.h
 */

#define INVALIDOID         0
/* numerics types */
#define INT2OID            21
#define INT4OID            23
#define INT8OID            20
#define FLOAT4OID         700
#define FLOAT8OID         701
#define NUMERICOID       1700
/* geo types */
#define POINTOID          600
#define LSEGOID           601
#define PATHOID           602
#define BOXOID            603
#define POLYGONOID        604
#define LINEOID           628 /* not supported yet */
#define CIRCLEOID         718
/* network types */
#define INETOID           869
#define CIDROID           650
#define MACADDROID        829
/* variable length types */
#define BPCHAROID        1042
#define VARCHAROID       1043
#define NAMEOID            19
#define TEXTOID            25
#define ZPBITOID         1560 /* not supported yet */
#define VARBITOID        1562 /* not supported yet */
#define BYTEAOID           17
/* date and time types */
#define DATEOID          1082
#define TIMEOID          1083
#define TIMETZOID        1266
#define TIMESTAMPOID     1114
#define TIMESTAMPTZOID   1184
#define INTERVALOID      1186
/* misc types */
#define CHAROID            18
#define BOOLOID            16
#define OIDOID             26
#define CASHOID           790
#define RECORDOID        2249
#define UUIDOID          2950
#define JSONOID          114
#define JSONBOID         3802
#define VOIDOID          2278
/* array types */
#define INT2ARRAYOID     1005
#define INT4ARRAYOID     1007
#define VARCHARARRAYOID  1015
#define INETARRAYOID     1041
