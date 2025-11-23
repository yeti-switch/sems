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

        // --- function_traits ---
        template <typename T> struct function_traits;

        // function pointer
        template <typename R, typename... Args> struct function_traits<R (*)(Args...)> {
            using args        = std::tuple<Args...>;
            using return_type = R;
        };

        // member function pointer
        template <typename R, typename C, typename... Args> struct function_traits<R (C::*)(Args...)> {
            using args        = std::tuple<Args...>;
            using return_type = R;
        };

        // const member function pointer
        template <typename R, typename C, typename... Args> struct function_traits<R (C::*)(Args...) const> {
            using args        = std::tuple<Args...>;
            using return_type = R;
        };

        template <typename Method> static constexpr bool is_sync_method()
        {
            using Args      = typename function_traits<Method>::args;
            using ProtoArgs = typename function_traits<rpc_handler *>::args;

            if constexpr (std::tuple_size_v<Args> < 2)
                return false;

            return std::is_same_v<std::tuple_element_t<0, Args>, std::tuple_element_t<0, ProtoArgs>> &&
                   std::is_same_v<std::tuple_element_t<1, Args>, std::tuple_element_t<1, ProtoArgs>>;
        }

        template <typename Method> static constexpr bool is_async_method()
        {
            using Args      = typename function_traits<Method>::args;
            using ProtoArgs = typename function_traits<async_rpc_handler *>::args;

            if constexpr (std::tuple_size_v<Args> < 3)
                return false;

            return std::is_same_v<std::tuple_element_t<0, Args>, std::tuple_element_t<0, ProtoArgs>> &&
                   std::is_same_v<std::tuple_element_t<1, Args>, std::tuple_element_t<1, ProtoArgs>> &&
                   std::is_same_v<std::tuple_element_t<2, Args>, std::tuple_element_t<2, ProtoArgs>>;
        }

        template <typename T> struct always_false : std::false_type {};

        template <class Method, class... Extra> RpcHandler(Method m, Extra &&...extra)
        {
            using CleanMethod = std::remove_cv_t<std::remove_reference_t<Method>>;
            auto tup          = std::forward_as_tuple(extra...);

            if constexpr (std::is_member_function_pointer_v<CleanMethod>) {
                static_assert(sizeof...(Extra) >= 1, "Need at least one extra for object instance");
                auto &obj = std::get<0>(tup);

                using ObjType = std::decay_t<decltype(obj)>;
                static_assert(std::is_pointer_v<ObjType> || std::is_reference_v<ObjType>,
                              "First extra argument must be object pointer or reference");

                auto rest_tuple =
                    std::apply([](auto &&, auto &&...rest) { return std::forward_as_tuple(rest...); }, tup);

                if constexpr (is_sync_method<CleanMethod>()) {
                    method_handler = [obj, m, rest_tuple](auto &&...args) {
                        std::apply([&](auto &&...hidden) { std::invoke(m, obj, args..., hidden...); }, rest_tuple);
                    };
                } else if constexpr (is_async_method<CleanMethod>()) {
                    method_async_handler = [obj, m, rest_tuple](auto &&...args) -> bool {
                        return std::apply([&](auto &&...hidden) { return std::invoke(m, obj, args..., hidden...); },
                                          rest_tuple);
                    };
                } else
                    static_assert(always_false<Method>(), "Unsupported function signature");
            } else if constexpr (is_sync_method<CleanMethod>()) {
                method_handler = [m, tup](auto &&...args) {
                    std::apply([&](auto &&...hidden) { std::invoke(m, args..., hidden...); }, tup);
                };
            } else if constexpr (is_async_method<CleanMethod>()) {
                method_async_handler = [m, tup](auto &&...args) -> bool {
                    return std::apply([&](auto &&...hidden) { return std::invoke(m, args..., hidden...); }, tup);
                };
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
