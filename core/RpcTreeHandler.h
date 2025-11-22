#pragma once

#include "AmApi.h"
#include "AmUtils.h"
#include "ampi/JsonRPCEvents.h"

#include <functional>
#include <type_traits>

class RpcTreeHandler : public AmDynInvoke {
  public:
    using rpc_handler       = void(const AmArg &args, AmArg &ret);
    using async_rpc_handler = bool(const string &connection_id, const AmArg &request_id, const AmArg &params);

    RpcTreeHandler(bool methods_tree = false);

    virtual ~RpcTreeHandler();

  protected:
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

        bool isMethod() const;
        bool operator()(const string &connection_id, const AmArg &request_id, const AmArg &args, AmArg &ret) const;
    };

    struct rpc_entry : public AmObject {
        RpcHandler handler;
        string     leaf_descr, func_descr, arg, arg_descr;

        std::optional<std::map<string, rpc_entry>> leaves;

        rpc_entry() {}
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

        bool isMethod() const { return handler.isMethod(); }
        bool hasLeafs() const { return leaves.has_value(); }
        bool hasLeaf(const char *leaf) const { return hasLeafs() && leaves->find(leaf) != leaves->end(); }
        bool hasLeaf(const string &leaf) const { return hasLeafs() && leaves->find(leaf) != leaves->end(); }
    };

    rpc_entry &reg_leaf(rpc_entry &parent, const string &name, const string &desc = "");

    template <typename T, typename... Args>
    rpc_entry &reg_method(rpc_entry &parent, const string &name, const string &descr, const string &func_descr,
                          T handler, Args &&...args);

    template <typename T, typename... Args>
    rpc_entry &reg_method_arg(rpc_entry &parent, const string &name, const string &descr, const string &func_descr,
                              const string &arg, const string &arg_descr, T handler, Args &&...args);

    virtual void init_rpc_tree() = 0;
    virtual void log_invoke(const string &method, const AmArg &args) const {}

  protected:
    rpc_entry root;
    bool      methods_tree;

    bool process_rpc_cmds(const string &connection_id, const AmArg &request_id, const rpc_entry &entry,
                          const string &method, const AmArg &args, AmArg &ret);
    bool process_rpc_cmds_methods_tree(const string &connection_id, const AmArg &request_id, const rpc_entry &entry,
                                       vector<string> &methods_tree, const AmArg &args, AmArg &ret);
    bool process_rpc_cmds_methods_tree_root(const string &connection_id, const AmArg &request_id,
                                            const rpc_entry &entry, const string &method, const AmArg &args,
                                            AmArg &ret);

    void serialize_methods_tree(const rpc_entry &entry, AmArg &tree);

  public:
    bool invoke_async(const string &connection_id, const AmArg &request_id, const string &method,
                      const AmArg &params) override;

    virtual void invoke(const string &method, const AmArg &args, AmArg &ret) override;

    virtual void get_methods_tree(AmArg &tree) override;
    void         init_rpc();

    bool is_methods_tree() override { return methods_tree; }
};

template <typename T, typename... Args>
RpcTreeHandler::rpc_entry &RpcTreeHandler::reg_method(rpc_entry &parent, const string &name, const string &descr,
                                                      const string &func_descr, T handler, Args &&...args)
{
    if (!parent.leaves.has_value())
        parent.leaves.emplace();
    auto ret =
        parent.leaves->emplace(name, rpc_entry(descr, RpcHandler(handler, std::forward<Args>(args)...), func_descr));
    return ret.first->second;
}

template <typename T, typename... Args>
RpcTreeHandler::rpc_entry &RpcTreeHandler::reg_method_arg(rpc_entry &parent, const string &name, const string &descr,
                                                          const string &func_descr, const string &arg,
                                                          const string &arg_descr, T handler, Args &&...args)
{
    if (!parent.leaves.has_value())
        parent.leaves.emplace();
    auto ret = parent.leaves->emplace(
        name, rpc_entry(descr, RpcHandler(handler, std::forward<Args>(args)...), func_descr, arg, arg_descr));
    return ret.first->second;
}
