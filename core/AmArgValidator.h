#pragma once

#include "AmArg.h"

#include <vector>
#include <string>

//TODO: support nested fields validation

class AmArgHashValidator
{
  public:
    struct Field {
        std::string name;
        bool mandatory;
        std::vector<AmArg::Type> allowed_types;
        std::function<bool(const AmArg &value)> validate_callback;
        Field() = delete;
        Field(
           const std::string &name,
           bool mandatory,
           std::initializer_list<AmArg::Type> allowed_types,
           std::function<bool(const AmArg &value)> callback = nullptr)
          : name(name),
            mandatory(mandatory),
            allowed_types(allowed_types),
            validate_callback(callback)
        {}
    };
  private:
    std::vector<Field> fields;
  public:
    AmArgHashValidator() = delete;
    AmArgHashValidator(std::initializer_list<Field> l);

    /** @brief validates AmArg object using predefined rules
     *  @arg a object to validate
     *  @return true if the object is valid
     */
    bool validate(const AmArg &a) const;
};
