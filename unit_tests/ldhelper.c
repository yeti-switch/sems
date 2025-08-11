/** this shared object file the dynamic linker MUST
 *  load before any other shared object, like libsems */

#include <dlfcn.h>
#include "ldhelper.h"

res_search_func_t real_res_search;
res_search_func_t mock_res_search;


__attribute__((constructor)) static void ldhelper_init(void)
{
    real_res_search = (res_search_func_t)dlsym(RTLD_NEXT, "res_search");
}

int res_search(const char *dname, int cl, int type, unsigned char *answer, int anslen)
{
    return mock_res_search ? mock_res_search(dname, cl, type, answer, anslen)
                           : real_res_search(dname, cl, type, answer, anslen);
}
