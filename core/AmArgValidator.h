#pragma once

#include "AmArg.h"

#include <vector>
#include <string>
#include <functional>

//TODO: support nested fields validation

class AmArgHashValidator
{
  public:
    struct Field {
        std::string name;
        bool mandatory;
        std::vector<AmArg::Type> allowed_types;
        std::function<bool(const AmArg &value)> validate_callback;
        AmArgHashValidator* nested_validator;

        Field() = delete;

        Field(
            const std::string &name,
            bool mandatory,
            std::initializer_list<AmArg::Type> allowed_types,
            std::function<bool(const AmArg &value)> callback = nullptr)
          : name(name),
            mandatory(mandatory),
            allowed_types(allowed_types),
            validate_callback(callback),
            nested_validator(nullptr)
        {}

        Field(
            const std::string &name,
            bool mandatory,
            std::initializer_list<AmArg::Type> allowed_types,
            AmArgHashValidator *nested_validator)
          : name(name),
            mandatory(mandatory),
            allowed_types(allowed_types),
            validate_callback(nullptr),
            nested_validator(nested_validator)
        {}
    };
  private:
    std::vector<Field> fields;

  public:
    AmArgHashValidator() = delete;
    AmArgHashValidator(std::initializer_list<Field> l);

    /** @brief validates AmArg object using predefined rules
     *  @param[in] a object to validate
     *  @arg[out] error validation error string
     *  @return true if the object is valid
     */
    bool validate(const AmArg &a, std::string &error) const;
};
