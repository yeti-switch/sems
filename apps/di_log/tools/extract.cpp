#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <DILog.h> //MAX_LINE_LEN

#define err(fmt,args...) \
    fprintf(stderr,fmt,##args);\
    return EXIT_FAILURE;

#define in_path argv[1]
#define out_path argv[2]

int main(int argc, char **argv)
{
    size_t ret;
    int lines = 0;
    FILE *in, *out = NULL;
    struct stat s;
    char buf[MAX_LINE_LEN];

    if(argc < 2) {
        err(
            "usage: %s filename [outfile]\n"
            "\textract strings from di_log buffer binary dump\n"
            "\tsave to outfile if specified and to stdout otherwise\n"
            "\t(compiled for %d di_log buffer entry len)\n",
            argv[0],MAX_LINE_LEN);
    }

    in = fopen(in_path,"rb");
    if(!in) {
        err("can't open input file '%s' for reading\n",in_path);
    }

    if(argc > 2) {
        if(stat(out_path,&s)==0) {
            err("output file '%s' already exists\n",out_path);
        }
        out = fopen(out_path,"w");
        if(!out) {
            err("can't open output file '%s' for writing\n",out_path);
            return EXIT_FAILURE;
        }
    }

    for(ret = fread(buf, MAX_LINE_LEN, 1, in);
        ret;
        ret = fread(buf, MAX_LINE_LEN, 1, in),
        lines++)
    {
        if(out) fprintf(out,"%s",buf);
        else printf("%s",buf);
    }

    fprintf(stderr,"%d lines extracted to %s\n",lines,
        out ? out_path : "stdout");

    return EXIT_SUCCESS;
}
