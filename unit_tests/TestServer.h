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
public:
    TestServer(){}

    void addResponse(const string& query, const AmArg& response) {
        responses.emplace(query, response);
    }

    void addError(const string& query, bool erase) {
        errors.emplace(query, erase);
    }

    bool isError(const string& query) {
        for(auto it = errors.begin();
            it != errors.end(); it++) {
            if(it->first == query) {
                if(it->second) errors.erase(it);
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
