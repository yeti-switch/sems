#include "RpcTreeHandler.h"

RpcTreeHandler::RpcTreeHandler(bool methods_tree)
    : methods_tree(methods_tree)
    , root_entry(nullptr)
{
}

RpcTreeHandler::~RpcTreeHandler()
{
    if (!isArgStruct(root))
        return;
    for (auto &e : *root.asStruct())
        free_methods_three(e.second);
    root.clear();
    if (root_entry)
        delete root_entry;
}


bool RpcTreeHandler::RpcHandler::isMethod()
{
    return method_handler != nullptr || method_async_handler != nullptr;
}

bool RpcTreeHandler::RpcHandler::operator()(const string &connection_id, const AmArg &request_id, const AmArg &args,
                                            AmArg &ret)
{
    if (method_async_handler)
        return method_async_handler(connection_id, request_id, args);

    method_handler(args, ret);
    return false;
}

bool RpcTreeHandler::process_rpc_cmds(const string &connection_id, const AmArg &request_id, const AmArg &cmds,
                                      const string &method, const AmArg &args, AmArg &ret)
{
    const char *list_method = "_list";
    if (method == list_method) {
        ret.assertArray();
        switch (cmds.getType()) {
        case AmArg::Struct:
        {
            AmArg::ValueStruct::const_iterator it = cmds.begin();
            for (; it != cmds.end(); ++it) {
                const AmArg &am_e = it->second;
                rpc_entry   *e    = reinterpret_cast<rpc_entry *>(am_e.asObject());
                AmArg        f;
                f.push(it->first);
                f.push(e->leaf_descr);
                ret.push(f);
            }
        } break;

        case AmArg::AObject:
        {
            rpc_entry *e = reinterpret_cast<rpc_entry *>(cmds.asObject());
            if (!e->func_descr.empty() && (!e->arg.empty() || e->hasLeafs())) {
                AmArg f;
                f.push("[Enter]");
                f.push(e->func_descr);
                ret.push(f);
            }
            if (!e->arg.empty()) {
                AmArg f;
                f.push(e->arg);
                f.push(e->arg_descr);
                ret.push(f);
            }
            if (e->hasLeafs()) {
                const AmArg                       &l  = e->leaves;
                AmArg::ValueStruct::const_iterator it = l.begin();
                for (; it != l.end(); ++it) {
                    const AmArg &am_e = it->second;
                    rpc_entry   *e    = reinterpret_cast<rpc_entry *>(am_e.asObject());
                    AmArg        f;
                    f.push(it->first);
                    f.push(e->leaf_descr);
                    ret.push(f);
                }
            }
        } break;

        default: throw AmArg::TypeMismatchException();
        }
        return false;
    }

    if (cmds.hasMember(method)) {
        const AmArg &l = cmds[method];
        if (l.getType() != AmArg::AObject)
            throw AmArg::TypeMismatchException();
        rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
        if (isArgArray(args) && args.size() > 0) {
            if (e->hasLeaf(args[0].asCStr())) {
                AmArg nargs = args, sub_method;
                nargs.pop(sub_method);
                return process_rpc_cmds(connection_id, request_id, e->leaves, sub_method.asCStr(), nargs, ret);
            } else if (args[0] == list_method) {
                AmArg nargs = args, sub_method;
                nargs.pop(sub_method);
                return process_rpc_cmds(connection_id, request_id, l, sub_method.asCStr(), nargs, ret);
            }
        }
        if (e->isMethod()) {
            if (isArgArray(args) && args.size() && strcmp(args.back().asCStr(), list_method) == 0) {
                if (!e->hasLeafs() && e->arg.empty())
                    ret.assertArray();
                return false;
            }

            return e->handler(connection_id, request_id, args, ret);
        }
        throw AmDynInvoke::NotImplemented("missed arg");
    }
    throw AmDynInvoke::NotImplemented("no matches with methods tree");
}

bool RpcTreeHandler::process_rpc_cmds_methods_tree_root(const string &connection_id, const AmArg &request_id,
                                                        const AmArg &cmds, const string &method, const AmArg &args,
                                                        AmArg &ret)
{
    vector<string> methods_tree = explode(method, ".");
    return process_rpc_cmds_methods_tree(connection_id, request_id, cmds, methods_tree, args, ret);
}

bool RpcTreeHandler::process_rpc_cmds_methods_tree(const string &connection_id, const AmArg &request_id,
                                                   const AmArg &cmds, vector<string> &methods_tree, const AmArg &args,
                                                   AmArg &ret)
{
    const char *list_method = "_list";

    if (methods_tree.empty()) {
        throw AmDynInvoke::Exception(-32603, "empty methods tree");
    }

    string method = *methods_tree.begin();
    methods_tree.erase(methods_tree.begin());

    if (method == list_method) {
        ret.assertArray();
        switch (cmds.getType()) {
        case AmArg::Struct:
        {
            AmArg::ValueStruct::const_iterator it = cmds.begin();
            for (; it != cmds.end(); ++it) {
                const AmArg &am_e = it->second;
                rpc_entry   *e    = reinterpret_cast<rpc_entry *>(am_e.asObject());
                AmArg        f;
                f.push(it->first);
                f.push(e->leaf_descr);
                ret.push(f);
            }
        } break;

        case AmArg::AObject:
        {
            rpc_entry *e = reinterpret_cast<rpc_entry *>(cmds.asObject());
            if (!e->func_descr.empty() && (!e->arg.empty() || e->hasLeafs())) {
                AmArg f;
                f.push("[Enter]");
                f.push(e->func_descr);
                ret.push(f);
            }
            if (!e->arg.empty()) {
                AmArg f;
                f.push(e->arg);
                f.push(e->arg_descr);
                ret.push(f);
            }
            if (e->hasLeafs()) {
                const AmArg                       &l  = e->leaves;
                AmArg::ValueStruct::const_iterator it = l.begin();
                for (; it != l.end(); ++it) {
                    const AmArg &am_e = it->second;
                    rpc_entry   *e    = reinterpret_cast<rpc_entry *>(am_e.asObject());
                    AmArg        f;
                    f.push(it->first);
                    f.push(e->leaf_descr);
                    ret.push(f);
                }
            }
        } break;

        default: throw AmArg::TypeMismatchException();
        } // switch
        return false;
    }

    if (cmds.hasMember(method)) {
        const AmArg &l = cmds[method];
        if (l.getType() != AmArg::AObject)
            throw AmArg::TypeMismatchException();

        rpc_entry *e = reinterpret_cast<rpc_entry *>(l.asObject());
        if (!methods_tree.empty()) {
            if (e->hasLeaf(methods_tree[0])) {
                return process_rpc_cmds_methods_tree(connection_id, request_id, e->leaves, methods_tree, args, ret);
            } else if (methods_tree[0] == list_method) {
                return process_rpc_cmds_methods_tree(connection_id, request_id, l, methods_tree, args, ret);
            } else {
                throw AmDynInvoke::Exception(-32601,
                                             string("no matches with methods tree. unknown part: ") + methods_tree[0]);
            }
        }
        if (e->isMethod()) {
            if ((!methods_tree.empty() && methods_tree.back() == list_method) ||
                (args.getType() == AmArg::Array && args.size() && isArgCStr(args.back()) &&
                 strcmp(args.back().asCStr(), list_method) == 0))
            {
                if (!e->hasLeafs() && e->arg.empty())
                    ret.assertArray();
                return false;
            }

            return e->handler(connection_id, request_id, args, ret);
        }
        throw AmDynInvoke::Exception(-32601, string("not completed method path. last element: ") + method);
    }
    throw AmDynInvoke::Exception(-32601, string("no matches with methods tree. unknown part: ") + method);
}

bool RpcTreeHandler::invoke_async(const string &connection_id, const AmArg &request_id, const string &method,
                                  const AmArg &params)
{
    log_invoke(method, params);

    bool  async_consumed;
    AmArg ret;

    if (methods_tree || method.find('.') != string::npos) {
        async_consumed = process_rpc_cmds_methods_tree_root(connection_id, request_id, root, method, params, ret);
    } else {
        async_consumed = process_rpc_cmds(connection_id, request_id, root, method, params, ret);
    }

    if (!async_consumed) {
        postJsonRpcReply(connection_id, request_id, ret);
    }

    return true;
}

void RpcTreeHandler::invoke(const string &method, const AmArg &args, AmArg &ret)
{
    static string empty;
    log_invoke(method, args);

    if (methods_tree || method.find('.') != string::npos)
        process_rpc_cmds_methods_tree_root(empty, empty, root, method, args, ret);
    else
        process_rpc_cmds(empty, empty, root, method, args, ret);
}

void RpcTreeHandler::serialize_methods_tree(AmArg &methods_root, AmArg &tree)
{
    if (!isArgAObject(methods_root))
        return;

    rpc_entry *e = reinterpret_cast<rpc_entry *>(methods_root.asObject());

    if (!e->hasLeafs())
        return;

    for (auto &l : *e->leaves.asStruct())
        serialize_methods_tree(l.second, tree[l.first]);
}

void RpcTreeHandler::get_methods_tree(AmArg &tree)
{
    for (auto &e : *root.asStruct())
        serialize_methods_tree(e.second, tree[e.first]);
}

void RpcTreeHandler::free_methods_three(AmArg &tree)
{
    if (!isArgAObject(tree))
        return;

    rpc_entry *e = reinterpret_cast<rpc_entry *>(tree.asObject());

    if (!e->hasLeafs()) {
        delete e;
        return;
    }

    for (auto &l : *e->leaves.asStruct())
        free_methods_three(l.second);

    delete e;
}

AmArg &RpcTreeHandler::reg_leaf(AmArg &parent, const string &name, const string &desc)
{
    rpc_entry *e = new rpc_entry(desc);
    parent[name] = e;
    return e->leaves;
}

void RpcTreeHandler::init_rpc()
{
    root_entry = new rpc_entry("root");
    root       = root_entry->leaves;
    init_rpc_tree();
}
