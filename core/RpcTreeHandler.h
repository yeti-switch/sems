#pragma once

#include "AmApi.h"

template<class C>
class RpcTreeHandler
  : public AmDynInvoke
{
    void process_rpc_cmds(
        const AmArg &cmds, const string& method,
        const AmArg& args, AmArg& ret);
    void process_rpc_cmds_methods_tree(
        const AmArg &cmds, vector<string> &methods_tree,
        const AmArg& args, AmArg& ret);
    void process_rpc_cmds_methods_tree_root(
        const AmArg &cmds, const string& method,
        const AmArg& args, AmArg& ret);
    bool methods_tree;
  public:
    using rpc_handler = void (const AmArg& args, AmArg& ret);

    RpcTreeHandler(bool methods_tree = false)
      : methods_tree(methods_tree)
    { }

  protected:
    AmArg root;

    struct rpc_entry
      : public AmObject
    {
        typedef typename C::rpc_handler C::*member_handler;
        member_handler handler;
        string leaf_descr,func_descr,arg,arg_descr;
        AmArg leaves;

        rpc_entry(string ld):
            handler(NULL), leaf_descr(ld) {}

        rpc_entry(string ld, member_handler h, string fd):
            leaf_descr(ld), handler(h), func_descr(fd) {}

        rpc_entry(string ld, member_handler h, string fd, string a, string ad):
            leaf_descr(ld), handler(h), func_descr(fd), arg(a), arg_descr(ad) {}

        bool isMethod(){ return handler!=NULL; }
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
    virtual void invoke(const string& method, const AmArg& args, AmArg& ret);
    void init_rpc();
};

template<class C>
void RpcTreeHandler<C>::process_rpc_cmds(const AmArg &cmds, const string& method,
                                      const AmArg& args, AmArg& ret)
{
    const char *list_method = "_list";
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
        }
        return;
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
                process_rpc_cmds(e->leaves,sub_method.asCStr(),nargs,ret);
                return;
            } else if(args[0]==list_method){
                AmArg nargs = args,sub_method;
                nargs.pop(sub_method);
                process_rpc_cmds(l,sub_method.asCStr(),nargs,ret);
                return;
            }
        }
        if(e->isMethod()){
            if(args.size()&&strcmp(args.back().asCStr(),list_method)==0){
                if(!e->hasLeafs()&&e->arg.empty())
                    ret.assertArray();
                return;
            }
            (static_cast<C &>(* this).*(e->handler))(args,ret);
            return;
        }
        throw AmDynInvoke::NotImplemented("missed arg");
    }
    throw AmDynInvoke::NotImplemented("no matches with methods tree");
}

template<class C>
void RpcTreeHandler<C>::process_rpc_cmds_methods_tree_root(
    const AmArg &cmds, const string& method,
    const AmArg& args, AmArg& ret)
{
    vector<string> methods_tree = explode(method,".");
    process_rpc_cmds_methods_tree(cmds,methods_tree,args,ret);
}

template<class C>
void RpcTreeHandler<C>::process_rpc_cmds_methods_tree(
    const AmArg &cmds, vector<string> &methods_tree,
    const AmArg& args, AmArg& ret)
{
    const char *list_method = "_list";

    if(methods_tree.empty()) {
        throw AmDynInvoke::NotImplemented("empty methods tree");
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
        return;
    }

    if(cmds.hasMember(method)){
        const AmArg &l = cmds[method];
        if(l.getType()!=AmArg::AObject)
            throw AmArg::TypeMismatchException();

        rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
        if(!methods_tree.empty()) {
            if(e->hasLeaf(methods_tree[0])) {
                process_rpc_cmds_methods_tree(e->leaves,methods_tree,args,ret);
                return;
            } else if(methods_tree[0]==list_method){
                process_rpc_cmds_methods_tree(l,methods_tree,args,ret);
                return;
            }
        }
        if(e->isMethod()){
            if(!methods_tree.empty() && methods_tree[0]==list_method)
            {
                if(!e->hasLeafs()&&e->arg.empty())
                    ret.assertArray();
                return;
            }
            (static_cast<C &>(* this).*(e->handler))(args,ret);
            return;
        }
        throw AmDynInvoke::NotImplemented("missed arg");
    }
    throw AmDynInvoke::NotImplemented("no matches with methods tree");
}

template<class C>
void RpcTreeHandler<C>::invoke(const string& method, const AmArg& args, AmArg& ret)
{
    log_invoke(method,args);
    //DBG("%s(%s)", method.c_str(), AmArg::print(args).c_str());
    if(methods_tree || method.find('.')!=string::npos)
        process_rpc_cmds_methods_tree_root(root,method,args,ret);
    else rocess_rpc_cmds(root,method,args,ret);
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
    rpc_entry *e = new rpc_entry("root");
    root = e->leaves;
    init_rpc_tree();
}
