#include "AmArgValidator.h"

#include <algorithm>
#include <sstream>

AmArgHashValidator::AmArgHashValidator(std::initializer_list<Field> l)
  : fields(l)
{}

bool AmArgHashValidator::validate(const AmArg &a, std::string &error) const
{
    error.clear();

    //DBG("validate(%s)",AmArg::print(a).data());
    if(!isArgStruct(a)) {
        error = "hash expected. got: " + AmArg::print(a);
        return false;
    }

    for(const auto &f: fields) {
        if(!a.hasMember(f.name)) {
            if(f.mandatory) {
                error = std::string("missed mandatory key '") + f.name + "' in: " + AmArg::print(a);
                return false;
            }
            continue;
        }

        const AmArg &fa = a[f.name];

        if(!f.allowed_types.empty()) {
            if(f.allowed_types.end()==std::find(f.allowed_types.begin(), f.allowed_types.end(), fa.getType())) {
                std::ostringstream ss;
                ss << "unexpected type " << AmArg::t2str(fa.getType()) <<
                      " for key '" << f.name << "' with value " << AmArg::print(fa);
                error = ss.str();
                return false;
            }
        }

        if(f.validate_callback) {
            if(!f.validate_callback(fa)) {
                error = std::string("got error from validator callback for key '") + f.name +
                        "' with value " + AmArg::print(fa);
                return false;
            }
        } else if(f.nested_validator) {
            if(isArgArray(fa)) {
                for(size_t i = 0; i < fa.size(); i++) {
                    if(!f.nested_validator->validate(fa[i], error))
                        return false;
                }
            } else {
                return f.nested_validator->validate(fa, error);
            }
        }
    }

    return true;
}
