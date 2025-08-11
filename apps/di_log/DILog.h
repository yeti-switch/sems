#include "AmApi.h"

#include <string>
#include <stdarg.h>

#define MAX_LINES    700000
#define MAX_LINE_LEN 512

class DILog : public AmLoggingFacility, public AmDynInvoke, public AmDynInvokeFactory, public AmConfigFactory {
  private:
    void          dumpLog(const char *path, AmArg &ret);
    string        dumpLog();
    static DILog *_instance;
    static char   ring_buf[MAX_LINES][MAX_LINE_LEN];
    static int    pos;

  public:
    DILog(const string &name);
    ~DILog();
    // DI factory
    AmDynInvoke *getInstance() override { return instance(); }
    // DI API
    static DILog *instance();
    void          invoke(const string &method, const AmArg &args, AmArg &ret) override;

    int onLoad() override;

    virtual int configure(const std::string &config) override;
    virtual int reconfigure(const std::string &config) override;
    // LF API
    // void log(int level, const char* fmt);
    void log(int level, pid_t pid, pid_t tid, const char *func, const char *file, int line, const char *msg,
             int msg_len) override;
};
