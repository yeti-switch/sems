#pragma once

#include "AmApi.h"
#include "AmUtils.h"
#include "ampi/JsonRPCEvents.h"

#include <functional>
#include <type_traits>

class RpcTreeHandler : public AmDynInvoke {
    bool process_rpc_cmds(const string &connection_id, const AmArg &request_id, const AmArg &cmds, const string &method,
                          const AmArg &args, AmArg &ret);
    bool process_rpc_cmds_methods_tree(const string &connection_id, const AmArg &request_id, const AmArg &cmds,
                                       vector<string> &methods_tree, const AmArg &args, AmArg &ret);
    bool process_rpc_cmds_methods_tree_root(const string &connection_id, const AmArg &request_id, const AmArg &cmds,
                                            const string &method, const AmArg &args, AmArg &ret);
    void serialize_methods_tree(AmArg &methods_root, AmArg &tree);
    bool methods_tree;

    void free_methods_three(AmArg &tree);

  public:
    using rpc_handler       = void(const AmArg &args, AmArg &ret);
    using async_rpc_handler = bool(const string &connection_id, const AmArg &request_id, const AmArg &params);

    RpcTreeHandler(bool methods_tree = false);

    virtual ~RpcTreeHandler();

  protected:
    AmArg root;

    class RpcHandler {
      private:
        std::function<rpc_handler>       method_handler;
        std::function<async_rpc_handler> method_async_handler;

      public:
        RpcHandler()
            : method_handler(nullptr)
            , method_async_handler(nullptr)
        {
        }

        template <typename T> struct always_false : std::false_type {};

        template <class Method, class... Extra> RpcHandler(Method m, Extra &&...extra)
        {
            using CleanMethod = std::remove_cv_t<std::remove_reference_t<Method>>;

            if constexpr (std::is_member_function_pointer_v<CleanMethod>) {
                static_assert(sizeof...(Extra) >= 1, "Need at least one extra for object instance");
                auto  tup = std::forward_as_tuple(extra...);
                auto &obj = std::get<0>(tup);

                using ObjType = std::decay_t<decltype(obj)>;
                static_assert(std::is_pointer_v<ObjType> || std::is_reference_v<ObjType>,
                              "First extra argument must be object pointer or reference");

                auto rest_tuple =
                    std::apply([](auto &&, auto &&...rest) { return std::forward_as_tuple(rest...); }, tup);

                if constexpr (std::is_invocable_r_v<void, CleanMethod, decltype(obj), const AmArg &, AmArg &>) {
                    method_handler = std::bind(m, obj, std::placeholders::_1, std::placeholders::_2);
                    std::apply(
                        [&](auto &&...args) {
                            if constexpr (sizeof...(args) > 0) {
                                method_handler = std::bind(method_handler, args...);
                            }
                        },
                        rest_tuple);
                } else if constexpr (std::is_invocable_r_v<bool, CleanMethod, decltype(obj), const string &,
                                                           const AmArg &, const AmArg &>)
                {
                    method_async_handler =
                        std::bind(m, obj, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
                    std::apply(
                        [&](auto &&...args) {
                            if constexpr (sizeof...(args) > 0) {
                                method_async_handler = std::bind(method_async_handler, args...);
                            }
                        },
                        rest_tuple);
                } else
                    static_assert(always_false<Method>(), "Unsupported function signature");
            } else if constexpr (std::is_same_v<Method, rpc_handler>) {
                method_handler =
                    std::bind(m, std::placeholders::_1, std::placeholders::_2, std::forward<Extra>(extra)...);
            } else if constexpr (std::is_same_v<Method, async_rpc_handler>) {
                method_async_handler = std::bind(m, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,
                                                 std::forward<Extra>(extra)...);
            } else
                static_assert(always_false<Method>(), "Unsupported function signature");
        }

        bool isMethod();
        bool operator()(const string &connection_id, const AmArg &request_id, const AmArg &args, AmArg &ret);
    };

    struct rpc_entry : public AmObject {
        RpcHandler handler;
        string     leaf_descr, func_descr, arg, arg_descr;
        AmArg      leaves;

        rpc_entry(string ld)
            : leaf_descr(ld)
        {
        }

        rpc_entry(string ld, const RpcHandler &h, string fd)
            : handler(h)
            , leaf_descr(ld)
            , func_descr(fd)
        {
        }

        rpc_entry(string ld, const RpcHandler &h, string fd, string a, string ad)
            : handler(h)
            , leaf_descr(ld)
            , func_descr(fd)
            , arg(a)
            , arg_descr(ad)
        {
        }

        bool isMethod() { return handler.isMethod(); }
        bool hasLeafs() { return leaves.getType() == AmArg::Struct; }
        bool hasLeaf(const char *leaf) { return hasLeafs() && leaves.hasMember(leaf); }
        bool hasLeaf(const string &leaf) { return hasLeafs() && leaves.hasMember(leaf); }
    };

    AmArg &reg_leaf(AmArg &parent, const string &name, const string &desc = "");

    template <typename T, typename... Args>
    AmArg &reg_method(AmArg &parent, const string &name, const string &descr, const string &func_descr, T handler,
                      Args &&...args);

    template <typename T, typename... Args>
    AmArg &reg_method_arg(AmArg &parent, const string &name, const string &descr, const string &func_descr,
                          const string &arg, const string &arg_descr, T handler, Args &&...args);

    virtual void init_rpc_tree() = 0;
    virtual void log_invoke(const string &method, const AmArg &args) const {}

  public:
    bool invoke_async(const string &connection_id, const AmArg &request_id, const string &method,
                      const AmArg &params) override;

    virtual void invoke(const string &method, const AmArg &args, AmArg &ret) override;

    virtual void get_methods_tree(AmArg &tree) override;
    void         init_rpc();

    bool is_methods_tree() override { return methods_tree; }

  private:
    rpc_entry *root_entry;
};

template <typename T, typename... Args>
AmArg &RpcTreeHandler::reg_method(AmArg &parent, const string &name, const string &descr, const string &func_descr,
                                  T handler, Args &&...args)
{
    rpc_entry *e = new rpc_entry(descr, RpcHandler(handler, std::forward<Args>(args)...), func_descr);
    parent[name] = e;
    return e->leaves;
}

template <typename T, typename... Args>
AmArg &RpcTreeHandler::reg_method_arg(AmArg &parent, const string &name, const string &descr, const string &func_descr,
                                      const string &arg, const string &arg_descr, T handler, Args &&...args)
{
    rpc_entry *e = new rpc_entry(descr, RpcHandler(handler, std::forward<Args>(args)...), func_descr, arg, arg_descr);
    parent[name] = e;
    return e->leaves;
}
