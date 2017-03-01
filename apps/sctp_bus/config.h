#pragma once

#include <confuse.h>
#include <memory>

#include "AmArg.h"

class cfg_reader {
  public:
    cfg_reader();
    ~cfg_reader();

    cfg_t *cfg;
    bool read(const string &path, cfg_opt_t *opts);
};
