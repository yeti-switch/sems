#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include <AmArg.h>

#include <vector>
#include <string>
#include <map>

using std::map;
using std::vector;
using std::string;

class TestServer
{
    map<string, AmArg> responses;
    map<string, bool> errors;
    map<string, string> errorcodes;
public:
    TestServer(){}

    void addResponse(const string& query, const AmArg& response) {
        responses.emplace(query, response);
    }

    void addError(const string& query, bool erase) {
        errors.emplace(query, erase);
    }

    void addErrorCodes(const string& query, const string& code) {
        errorcodes.emplace(query, code);
    }

    bool isError(const string& query, string& code) {
        for(auto it = errors.begin();
            it != errors.end(); it++) {
            if(it->first == query) {
                code = errorcodes[query];
                if(it->second) {
                    errors.erase(it);
                    errorcodes.erase(query);
                }
                return true;
            }
        }
        return false;
    }

    AmArg& getResponse(const string& query) {
        return responses[query];
    }

    void clear() {
        responses.clear();
        errors.clear();
    }
};

#endif/*TEST_SERVER_H*/
