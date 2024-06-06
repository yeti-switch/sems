#pragma once

#include "AmThread.h"

#include <vector>
#include <functional>

using std::vector;
using std::function;

template<typename Item>
class AmConcurrentVector: protected vector<Item>
{
protected:
    AmMutex mutex;

public:
    typedef function<bool(Item item)> Predicate;
    typedef function<void(Item item)> Result;
    typedef function<void(vector<Item> items)> MultipleResult;
    typedef function<void(Item item, bool& stop)> Iterator;
    typedef function<void()> Completed;

    void addItem(Item item, Completed completed = nullptr) {
        AmLock l(mutex);
        this->push_back(item);
        if(completed) completed();
    }

    void addItems(const vector<Item>& items, Completed completed = nullptr) {
        AmLock l(mutex);
        this->insert(this->end(), items.begin(), items.end());
        if(completed) completed();
    }

    void findItem(Predicate predicate, Result result) {
        AmLock l(mutex);
        for(auto it = this->begin(); it != this->end(); ++it) {
            auto item = *it;
            if(predicate(item)) {
                result(item);
                break;
            }
        }
    }

    void findItems(Predicate predicate, MultipleResult result) {
        AmLock l(mutex);
        vector<Item> res;
        for(auto it = this->begin(); it != this->end(); ++it) {
            auto item = *it;
            if(predicate(item))
                res.push_back(item);
        }

        result(res);
    }

    void iterateItems(Iterator iterator, Completed completed = nullptr) {
        AmLock l(mutex);
        bool stop = false;
        for(auto it = this->begin(); it != this->end(); ++it) {
            auto item = *it;
            iterator(item, stop);
            if(stop) break;
        }
        if(completed) completed();
    }

    void iterateItems(Predicate predicate, Iterator iterator, Completed completed = nullptr) {
        AmLock l(mutex);
        bool stop = false;
        for(auto it = this->begin(); it != this->end(); ++it) {
            auto item = *it;
            if (predicate(item)) {
                iterator(item, stop);
                if(stop) break;
            }
        }
        if(completed) completed();
    }

    void removeItem(Predicate predicate, Completed completed = nullptr) {
        AmLock l(mutex);
        for(auto it = this->begin(); it != this->end(); ++it) {
            auto item = *it;
            if(predicate(item)) {
                this->erase(it);
                delete item;
                break;
            }
        }
        if(completed) completed();
    }

    void removeItems(Completed completed = nullptr) {
        AmLock l(mutex);
        for(auto it = this->begin(); it != this->end();) {
            auto item = *it;
            it = this->erase(it);
            delete item;
        }
        if(completed) completed();
    }

    void removeItems(Predicate predicate, Completed completed = nullptr) {
        AmLock l(mutex);
        for(auto it = this->begin(); it != this->end();) {
            auto item = *it;
            if(predicate(item)) {
                it = this->erase(it);
                delete item;
                continue;
            }

            ++it;
        }
        if(completed) completed();
    }
};
