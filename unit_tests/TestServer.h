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
    struct tail
    {
        time_t time;
        int current;
        int count;
    };
    map<string, struct tail> tails;
public:
    TestServer(){}

    void addResponse(const string& query, const AmArg& response) {
        responses.emplace(query, response);
    }

    void addError(const string& query, bool erase) {
        errors.emplace(query, erase);
    }

    void addTail(const string& query, int sec) {
        struct tail t{.time = time(0), .current = 0, .count = sec};
        tails.emplace(query, t);
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
    
    bool checkTail(const string& query) {
        auto it = tails.find(query);
        if(it != tails.end()) {
            if(time(0) != it->second.time) {
                it->second.time = time(0);
                it->second.current++;
                return it->second.current != it->second.count;
            }
            return true;
        }
        return false;
    }

    void clear() {
        responses.clear();
        errors.clear();
    }
};

#endif/*TEST_SERVER_H*/
