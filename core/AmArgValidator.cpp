#include "AmArgValidator.h"

#include "log.h"

#include <algorithm>

AmArgHashValidator::AmArgHashValidator(std::initializer_list<Field> l)
  : fields(l)
{}

bool AmArgHashValidator::validate(const AmArg &a) const
{
    //DBG("validate(%s)",AmArg::print(a).data());
    if(!isArgStruct(a)) {
        ERROR("hash expected. got: %s", AmArg::print(a).data());
        return false;
    }

    for(const auto &f: fields) {
        if(!a.hasMember(f.name)) {
            if(f.mandatory) {
                ERROR("missed mandatory key '%s' in: %s", f.name.data(), AmArg::print(a).data());
                return false;
            }
            continue;
        }

        const AmArg &fa = a[f.name];

        if(!f.allowed_types.empty()) {
            if(f.allowed_types.end()==std::find(f.allowed_types.begin(), f.allowed_types.end(), fa.getType())) {
                ERROR("unexpected type %s for key '%s' with value %s",
                      AmArg::t2str(fa.getType()), f.name.data(), AmArg::print(fa).data());
                return false;
            }
        }

        if(f.validate_callback) {
            if(!f.validate_callback(fa)) {
                ERROR("got error from validator callback for key '%s' with value: %s",
                      f.name.data(), AmArg::print(fa).data());
                return false;
            }
        }
    }

    return true;
}
