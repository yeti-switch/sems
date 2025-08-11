#ifndef TEST_SERVER_H
#define TEST_SERVER_H

#include <AmArg.h>

#include <vector>
#include <string>
#include <map>

#include <time.h>
#include <unistd.h>

using std::map;
using std::string;
using std::vector;

class TestServer {
    map<string, AmArg>  responses;
    map<string, bool>   errors;
    map<string, string> errorcodes;
    bool                is_sync_error;
    struct tail {
        time_t time;
        int    current;
        int    count;
    };
    map<string, struct tail> tails;

  public:
    TestServer()
        : is_sync_error(false)
    {
    }

    void addResponse(const string &query, const AmArg &response) { responses[query].push(response); }

    void addError(const string &query, bool erase) { errors.emplace(query, erase); }

    void addTail(const string &query, int sec)
    {
        struct tail t{ .time = time(0), .current = 0, .count = sec };
        tails.emplace(query, t);
    }

    void addErrorCodes(const string &query, const string &code) { errorcodes.emplace(query, code); }

    bool isError(const string &query, string &code)
    {
        for (auto it = errors.begin(); it != errors.end(); it++) {
            if (it->first == query) {
                code = errorcodes[query];
                if (it->second) {
                    errors.erase(it);
                    errorcodes.erase(query);
                }
                return true;
            }
        }
        return false;
    }

    bool isSyncError() { return is_sync_error; }
    void setSyncError() { is_sync_error = true; }
    bool getResponse(const string &query, AmArg &res)
    {
        if (responses.find(query) == responses.end())
            return false;
        if (!responses[query].size())
            return false;
        res = responses[query][0];
        responses[query].erase((size_t)0);
        return true;
    }

    bool checkTail(const string &query)
    {
        auto it = tails.find(query);
        if (it != tails.end()) {
            if (time(0) != it->second.time) {
                it->second.time = time(0);
                if (it->second.current != it->second.count)
                    it->second.current++;
                if (it->second.current < it->second.count) {
                    sleep(1);
                    return true;
                }
                return false;
            }
            return true;
        }
        return false;
    }

    void clearTail(const string &query)
    {
        auto it = tails.find(query);
        if (it != tails.end()) {
            it->second.current = 0;
        }
    }

    void clear()
    {
        responses.clear();
        errors.clear();
        is_sync_error = false;
    }
};

#endif /*TEST_SERVER_H*/
