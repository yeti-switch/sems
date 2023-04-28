#pragma once

#include <confuse.h>
#include <memory>

#include "AmArg.h"

class cfg_reader {
    std::string mod_name;
  public:
    cfg_reader(const std::string& mod_name);
    ~cfg_reader();

    cfg_t *cfg;
    bool read(const std::string &config, cfg_opt_t *opts);
};
