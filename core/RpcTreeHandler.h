#pragma once

#include "AmApi.h"
#include "AmUtils.h"
#include "ampi/JsonRPCEvents.h"

template<class C>
class RpcTreeHandler
  : public AmDynInvoke
{
    bool process_rpc_cmds(
        const string& connection_id,
        const AmArg& request_id,
        const AmArg &cmds, const string& method,
        const AmArg& args, AmArg& ret);
    bool process_rpc_cmds_methods_tree(
        const string& connection_id,
        const AmArg& request_id,
        const AmArg &cmds, vector<string> &methods_tree,
        const AmArg& args, AmArg& ret);
    bool process_rpc_cmds_methods_tree_root(
        const string& connection_id,
        const AmArg& request_id,
        const AmArg &cmds, const string& method,
        const AmArg& args, AmArg& ret);
    void serialize_methods_tree(AmArg &methods_root, AmArg &tree);
    bool methods_tree;

    void free_methods_three(AmArg &tree);

  public:
    using rpc_handler = void (const AmArg& args, AmArg& ret);
    using async_rpc_handler =
        bool (
            const string& connection_id,
            const AmArg& request_id,
            const AmArg& params);

    RpcTreeHandler(bool methods_tree = false)
      : methods_tree(methods_tree),
        root_entry(nullptr)
    { }

    virtual ~RpcTreeHandler()
    {
        if(!isArgStruct(root))
            return;
        for(auto &e : *root.asStruct())
            free_methods_three(e.second);
        root.clear();
        if(root_entry)
            delete root_entry;
    }


  protected:
    AmArg root;

    struct rpc_entry
      : public AmObject
    {
        typedef typename C::rpc_handler C::*member_handler;
        typedef typename C::async_rpc_handler C::*async_member_handler;

        member_handler handler;
        async_member_handler async_handler;

        string leaf_descr,func_descr,arg,arg_descr;
        AmArg leaves;

        rpc_entry(string ld):
            handler(nullptr), leaf_descr(ld) {}

        rpc_entry(string ld, member_handler h, string fd):
            leaf_descr(ld),
            handler(h), async_handler(nullptr),
            func_descr(fd)
        {}

        rpc_entry(string ld, member_handler h, string fd, string a, string ad):
            leaf_descr(ld),
            handler(h), async_handler(nullptr),
            func_descr(fd), arg(a), arg_descr(ad)
        {}

        rpc_entry(string ld, async_member_handler h, string fd):
            leaf_descr(ld),
            handler(nullptr), async_handler(h),
            func_descr(fd)
        {}

        rpc_entry(string ld, async_member_handler h, string fd, string a, string ad):
            leaf_descr(ld),
            handler(nullptr), async_handler(h),
            func_descr(fd), arg(a), arg_descr(ad)
        {}

        bool isMethod(){ return handler!=nullptr || async_handler!=nullptr; }
        bool hasLeafs(){ return leaves.getType()==AmArg::Struct; }
        bool hasLeaf(const char *leaf){ return hasLeafs()&&leaves.hasMember(leaf); }
        bool hasLeaf(const string &leaf){ return hasLeafs()&&leaves.hasMember(leaf); }
    };

    AmArg &reg_leaf(AmArg &parent,const string &name,const string &desc = "");

    template<typename T>
    AmArg &reg_method(
        AmArg &parent,const string &name,const string &descr,
        T func, const string &func_descr = "");

    template<typename T>
    AmArg &reg_method_arg(
        AmArg &parent,const string &name,const string &descr,
        T func, const string &func_descr,
        const string &arg, const string &arg_descr);

    virtual void init_rpc_tree() = 0;
    virtual void log_invoke(const string& method, const AmArg& args) const { }

  public:
    bool invoke_async(
        const string& connection_id,
        const AmArg& request_id,
        const string& method,
        const AmArg& params) override;

    virtual void invoke(
        const string& method,
        const AmArg& args,
        AmArg& ret) override;

    virtual void get_methods_tree(AmArg &tree);
    void init_rpc();

    bool is_methods_tree() { return methods_tree; }

  private:
    rpc_entry *root_entry;
};

template<class C>
bool RpcTreeHandler<C>::process_rpc_cmds(
    const string& connection_id,
    const AmArg& request_id,
    const AmArg &cmds, const string& method,
    const AmArg& args, AmArg& ret)
{
    const char *list_method = "_list";
    if(method==list_method) {
        ret.assertArray();
        switch(cmds.getType()){
            case AmArg::Struct: {
                AmArg::ValueStruct::const_iterator it = cmds.begin();
                for(;it!=cmds.end();++it){
                    const AmArg &am_e = it->second;
                    rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
                    AmArg f;
                    f.push(it->first);
                    f.push(e->leaf_descr);
                    ret.push(f);
                }
            } break;

            case AmArg::AObject: {
                rpc_entry *e = reinterpret_cast<rpc_entry *>(cmds.asObject());
                if(!e->func_descr.empty()&&(!e->arg.empty()||e->hasLeafs())){
                    AmArg f;
                    f.push("[Enter]");
                    f.push(e->func_descr);
                    ret.push(f);
                }
                if(!e->arg.empty()){
                    AmArg f;
                    f.push(e->arg);
                    f.push(e->arg_descr);
                    ret.push(f);
                }
                if(e->hasLeafs()){
                    const AmArg &l = e->leaves;
                    AmArg::ValueStruct::const_iterator it = l.begin();
                    for(;it!=l.end();++it){
                        const AmArg &am_e = it->second;
                        rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
                        AmArg f;
                        f.push(it->first);
                        f.push(e->leaf_descr);
                        ret.push(f);
                    }
                }
            } break;

            default:
                throw AmArg::TypeMismatchException();
        }
        return false;
    }

    if(cmds.hasMember(method)){
        const AmArg &l = cmds[method];
        if(l.getType()!=AmArg::AObject)
            throw AmArg::TypeMismatchException();
        rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
        if(args.size()>0){
            if(e->hasLeaf(args[0].asCStr())){
                AmArg nargs = args,sub_method;
                nargs.pop(sub_method);
                return process_rpc_cmds(
                    connection_id, request_id,
                    e->leaves,sub_method.asCStr(),nargs,ret);
            } else if(args[0]==list_method){
                AmArg nargs = args,sub_method;
                nargs.pop(sub_method);
                return process_rpc_cmds(
                    connection_id, request_id,
                    l,sub_method.asCStr(),nargs,ret);
            }
        }
        if(e->isMethod()) {
            if(args.size()&&strcmp(args.back().asCStr(),list_method)==0){
                if(!e->hasLeafs()&&e->arg.empty())
                    ret.assertArray();
                return false;
            }

            if(e->async_handler) {
                return
                    (static_cast<C &>(* this).*(e->async_handler))(
                        connection_id,request_id, args);
            }

            (static_cast<C &>(* this).*(e->handler))(args,ret);
            return false;
        }
        throw AmDynInvoke::NotImplemented("missed arg");
    }
    throw AmDynInvoke::NotImplemented("no matches with methods tree");
}

template<class C>
bool RpcTreeHandler<C>::process_rpc_cmds_methods_tree_root(
    const string& connection_id,
    const AmArg& request_id,
    const AmArg &cmds, const string& method,
    const AmArg& args, AmArg& ret)
{
    vector<string> methods_tree = explode(method,".");
    return process_rpc_cmds_methods_tree(
        connection_id, request_id,
        cmds,methods_tree,args,ret);
}

template<class C>
bool RpcTreeHandler<C>::process_rpc_cmds_methods_tree(
    const string& connection_id,
    const AmArg& request_id,
    const AmArg &cmds, vector<string> &methods_tree,
    const AmArg& args, AmArg& ret)
{
    const char *list_method = "_list";

    if(methods_tree.empty()) {
        throw AmDynInvoke::Exception(-32603,"empty methods tree");
    }

    string method = *methods_tree.begin();
    methods_tree.erase(methods_tree.begin());

    if(method==list_method){
        ret.assertArray();
        switch(cmds.getType()){
            case AmArg::Struct: {
                AmArg::ValueStruct::const_iterator it = cmds.begin();
                for(;it!=cmds.end();++it){
                    const AmArg &am_e = it->second;
                    rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
                    AmArg f;
                    f.push(it->first);
                    f.push(e->leaf_descr);
                    ret.push(f);
                }
            } break;

            case AmArg::AObject: {
                rpc_entry *e = reinterpret_cast<rpc_entry *>(cmds.asObject());
                if(!e->func_descr.empty()&&(!e->arg.empty()||e->hasLeafs())){
                    AmArg f;
                    f.push("[Enter]");
                    f.push(e->func_descr);
                    ret.push(f);
                }
                if(!e->arg.empty()){
                    AmArg f;
                    f.push(e->arg);
                    f.push(e->arg_descr);
                    ret.push(f);
                }
                if(e->hasLeafs()){
                    const AmArg &l = e->leaves;
                    AmArg::ValueStruct::const_iterator it = l.begin();
                    for(;it!=l.end();++it){
                        const AmArg &am_e = it->second;
                        rpc_entry *e = reinterpret_cast<rpc_entry *>(am_e.asObject());
                        AmArg f;
                        f.push(it->first);
                        f.push(e->leaf_descr);
                        ret.push(f);
                    }
                }
            } break;

            default:
                throw AmArg::TypeMismatchException();
        } //switch
        return false;
    }

    if(cmds.hasMember(method)){
        const AmArg &l = cmds[method];
        if(l.getType()!=AmArg::AObject)
            throw AmArg::TypeMismatchException();

        rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
        if(!methods_tree.empty()) {
            if(e->hasLeaf(methods_tree[0])) {
                return process_rpc_cmds_methods_tree(
                    connection_id, request_id,
                    e->leaves,methods_tree,args,ret);
            } else if(methods_tree[0]==list_method){
                return process_rpc_cmds_methods_tree(
                    connection_id, request_id,
                    l,methods_tree,args,ret);
            } else {
                throw AmDynInvoke::Exception(-32601,
                    string("no matches with methods tree. unknown part: ") +
                    methods_tree[0]);
            }
        }
        if(e->isMethod()){
            if((!methods_tree.empty() && methods_tree.back()==list_method)
               || (args.getType() == AmArg::Array &&
                   args.size() &&
                   isArgCStr(args.back()) &&
                   strcmp(args.back().asCStr(),list_method)==0))
            {
                if(!e->hasLeafs()&&e->arg.empty())
                    ret.assertArray();
                return false;
            }

            if(e->async_handler) {
                return
                    (static_cast<C &>(* this).*(e->async_handler))(
                        connection_id,request_id, args);
            }

            (static_cast<C &>(* this).*(e->handler))(args,ret);

            return false;
        }
        throw AmDynInvoke::Exception(-32601,
            string("not completed method path. last element: ") + method);
    }
    throw AmDynInvoke::Exception(-32601,
        string("no matches with methods tree. unknown part: ") + method);
}

template<class C>
bool RpcTreeHandler<C>::invoke_async(
    const string& connection_id,
    const AmArg& request_id,
    const string& method,
    const AmArg& params)
{
    log_invoke(method,params);

    bool async_consumed;
    AmArg ret;

    if(methods_tree || method.find('.')!=string::npos) {
        async_consumed = process_rpc_cmds_methods_tree_root(
            connection_id, request_id,
            root,method,params,ret);
    } else {
        async_consumed = process_rpc_cmds(
            connection_id, request_id,
            root,method,params,ret);
    }

    if(!async_consumed) {
        postJsonRpcReply(
            connection_id,
            request_id,
            ret);
    }

    return true;
}

template<class C>
void RpcTreeHandler<C>::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    static string empty;
    log_invoke(method,args);

    if(methods_tree || method.find('.')!=string::npos)
        process_rpc_cmds_methods_tree_root(
            empty,empty,root,method,args,ret);
    else process_rpc_cmds(
            empty,empty,root,method,args,ret);
}

template<class C>
void RpcTreeHandler<C>::serialize_methods_tree(AmArg &methods_root, AmArg &tree)
{
    if(!isArgAObject(methods_root))
        return;

    rpc_entry *e = reinterpret_cast<rpc_entry *>(methods_root.asObject());

    if(!e->hasLeafs())
        return;

    for(auto &l : *e->leaves.asStruct())
        serialize_methods_tree(l.second,tree[l.first]);
}

template<class C>
void RpcTreeHandler<C>::get_methods_tree(AmArg &tree)
{
    for(auto &e : *root.asStruct())
        serialize_methods_tree(e.second,tree[e.first]);
}

template<class C>
void RpcTreeHandler<C>::free_methods_three(AmArg &tree) {
    if(!isArgAObject(tree))
        return;

    rpc_entry *e = reinterpret_cast<rpc_entry *>(tree.asObject());

    if(!e->hasLeafs()) {
        delete e;
        return;
    }

    for(auto &l : *e->leaves.asStruct())
        free_methods_three(l.second);

    delete e;
}

template<class C>
AmArg &RpcTreeHandler<C>::reg_leaf(AmArg &parent,const string &name,const string &desc)
{
    rpc_entry *e = new rpc_entry(desc);
    parent[name] = e;
    return e->leaves;
}

template<class C>
template<typename T>
AmArg &RpcTreeHandler<C>::reg_method(
    AmArg &parent,const string &name,const string &descr,
    T func,const string &func_descr)
{
    rpc_entry *e = new rpc_entry(descr,func,func_descr);
    parent[name] = e;
    return e->leaves;
}

template<class C>
template<typename T>
AmArg &RpcTreeHandler<C>::reg_method_arg(
    AmArg &parent,const string &name,const string &descr,
    T func,const string &func_descr,
    const string &arg, const string &arg_descr)
{
    rpc_entry *e = new rpc_entry(descr,func,func_descr,arg,arg_descr);
    parent[name] = e;
    return e->leaves;
}

template<class C>
void RpcTreeHandler<C>::init_rpc()
{
    root_entry = new rpc_entry("root");
    root = root_entry->leaves;
    init_rpc_tree();
}
