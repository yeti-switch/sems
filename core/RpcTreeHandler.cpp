#include "RpcTreeHandler.h"

RpcTreeHandler::RpcTreeHandler() {}

RpcTreeHandler::~RpcTreeHandler() {}


bool RpcTreeHandler::RpcHandler::isMethod() const
{
    return method_handler != nullptr || method_async_handler != nullptr;
}

bool RpcTreeHandler::RpcHandler::operator()(const string &connection_id, const AmArg &request_id, const AmArg &args,
                                            AmArg &ret) const
{
    if (method_async_handler)
        return method_async_handler(connection_id, request_id, args);

    method_handler(args, ret);
    return false;
}

bool RpcTreeHandler::process_rpc_cmds_methods_tree_root(const string &connection_id, const AmArg &request_id,
                                                        const rpc_entry &entry, const string &method, const AmArg &args,
                                                        AmArg &ret)
{
    vector<string> methods_tree = explode(method, ".");
    return process_rpc_cmds_methods_tree(connection_id, request_id, entry, methods_tree, args, ret);
}

bool RpcTreeHandler::process_rpc_cmds_methods_tree(const string &connection_id, const AmArg &request_id,
                                                   const rpc_entry &entry, vector<string> &methods_tree,
                                                   const AmArg &args, AmArg &ret)
{
    const char *list_method = "_list";

    if (methods_tree.empty()) {
        throw AmDynInvoke::Exception(-32603, "empty methods tree");
    }

    string method = *methods_tree.begin();
    methods_tree.erase(methods_tree.begin());

    if (method == list_method) {
        ret.assertArray();
        if (!entry.isMethod() && !entry.hasLeafs()) {
            throw AmArg::TypeMismatchException();
        }
        if (entry.isMethod()) {
            if (!entry.func_descr.empty() && (!entry.arg.empty() || entry.hasLeafs())) {
                AmArg f;
                f.push("[Enter]");
                f.push(entry.func_descr);
                ret.push(f);
            }
            if (!entry.arg.empty()) {
                AmArg f;
                f.push(entry.arg);
                f.push(entry.arg_descr);
                ret.push(f);
            }
        }
        if (entry.hasLeafs()) {
            auto it = entry.leaves->begin();
            for (; it != entry.leaves->end(); ++it) {
                const rpc_entry &e = it->second;
                AmArg            f;
                string           name = it->first;
                std::ranges::replace(name, '_', '-');
                f.push(name);
                f.push(e.leaf_descr);
                ret.push(f);
            }
        }
        return false;
    }

    if (entry.hasLeaf(method)) {
        const rpc_entry &e = entry.leaves->at(method);
        if (!methods_tree.empty()) {
            if (e.hasLeaf(methods_tree[0]) || methods_tree[0] == list_method) {
                return process_rpc_cmds_methods_tree(connection_id, request_id, e, methods_tree, args, ret);
            } else {
                throw AmDynInvoke::Exception(-32601,
                                             string("no matches with methods tree. unknown part: ") + methods_tree[0]);
            }
        }
        if (e.isMethod()) {
            if ((!methods_tree.empty() && methods_tree.back() == list_method) ||
                (args.getType() == AmArg::Array && args.size() && isArgCStr(args.back()) &&
                 strcmp(args.back().asCStr(), list_method) == 0))
            {
                if (!e.hasLeafs() && e.arg.empty())
                    ret.assertArray();
                return false;
            }

            return e.handler(connection_id, request_id, args, ret);
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

    async_consumed = process_rpc_cmds_methods_tree_root(connection_id, request_id, root, method, params, ret);
    if (!async_consumed) {
        postJsonRpcReply(connection_id, request_id, ret);
    }

    return true;
}

void RpcTreeHandler::invoke(const string &method, const AmArg &args, AmArg &ret)
{
    static string empty;
    log_invoke(method, args);
    process_rpc_cmds_methods_tree_root(empty, empty, root, method, args, ret);
}

void RpcTreeHandler::serialize_methods_tree(const rpc_entry &entry, AmArg &tree)
{
    if (!entry.hasLeafs())
        return;

    for (const auto &l : *entry.leaves) {
        string name = l.first;
        std::ranges::replace(name, '_', '-');
        serialize_methods_tree(l.second, tree[name]);
    }
}

void RpcTreeHandler::get_methods_tree(AmArg &tree)
{
    if (!root.hasLeafs())
        return;

    for (const auto &e : *root.leaves) {
        string name = e.first;
        std::ranges::replace(name, '_', '-');
        serialize_methods_tree(e.second, tree[name]);
    }
}

RpcTreeHandler::rpc_entry &RpcTreeHandler::reg_leaf(rpc_entry &parent, const string &name, const string &desc)
{
    if (!parent.leaves.has_value())
        parent.leaves.emplace();
    auto ret = parent.leaves->emplace(name, rpc_entry(desc));
    return ret.first->second;
}

void RpcTreeHandler::init_rpc()
{
    init_rpc_tree();
}
