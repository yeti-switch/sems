#include "log.h"
#include "AmIdentity.h"
#include "sems.h"
#include "cJSON.h"
#include "jsonArg.h"
#include "AmUtils.h"

#include <botan/x509_ca.h>
#include "botan/x509_ext.h"
#include <botan/pkix_types.h>
#include <botan/system_rng.h>
#include <botan/pkcs8.h>

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>

#include <string>
#include <map>
#include <set>
#include <functional>
#include <fstream>
#include <iostream>

using namespace std;

static char *getFormattedJSON(const string &s)
{
    static char buf[2048];
    char *ret = nullptr;

    auto j = cJSON_Parse(s.data());
    if(!j) return nullptr;

    if(cJSON_PrintPreallocated(j, buf, 2048, 1))
        ret = buf;

    cJSON_Delete(j);

    return ret;
}

class commands_dispatcher
{
    using f = function<int (int, char *[])>;
    map<string, f> handlers;

  public:
    commands_dispatcher &add(const string &cmd, f handler)
    {
        handlers.emplace(cmd, handler);
        return *this;
    }

    int dispatch(int argc, char *argv[])
    {
        if(argc < 2) {
            fprintf(
                stderr, "missed action. type \"help\" for a list\n");
            return 1;
        }
        if(0==strcmp(argv[1],"help")) {
            printf("Commands:\n");
            for(auto &h : handlers) {
                printf("  %s\n", h.first.data());
            }
            return 0;
        }

        auto it = handlers.find(argv[1]);
        if(it==handlers.end()) {
            fprintf(
                stderr, "Invalid command '%s'; type \"help\" for a list.\n",
                argv[1]);
            return 1;
        }
        return it->second(argc, argv);
    }
};

class options_parser
{
    using callback_function_t = function<void (const char *value)>;

    string usage_opts;

    struct opt_t {
        callback_function_t callback;
        string opt_desc_left;
        string opt_desc_right;
        bool has_arg;

        opt_t(callback_function_t callback,
              const string &opt_desc_left, const string opt_desc_right,
              bool has_arg = false)
          : callback(callback),
            opt_desc_left(opt_desc_left),
            opt_desc_right(opt_desc_right),
            has_arg(has_arg)
        {}
    };
    map<char, opt_t> opts;
    set<char> parsed_options;

    struct long_opt_t {
        string name;
        callback_function_t callback;
        int has_arg;
        string opt_desc_left;
        string opt_desc_right;
        long_opt_t(
            string name,
            callback_function_t callback,
            const string &opt_desc_left, const string opt_desc_right,
            int has_arg = no_argument)
          : name(name),
            callback(callback),
            has_arg(has_arg),
            opt_desc_left(opt_desc_left),
            opt_desc_right(opt_desc_right)
        {}
    };
    vector<long_opt_t> long_opts;
    set<string> parsed_long_options;

  public:
    options_parser(const string &usage_opts)
      : usage_opts(usage_opts)
    {}

    options_parser &add(char opt,
                        const string &opt_desc_left,
                        const string &opt_desc_right,
                        bool has_arg = false,
                        callback_function_t callback = nullptr)
    {
        opts.try_emplace(
            opt,
            callback,
            opt_desc_left, opt_desc_right,
            has_arg);
        return *this;
    }

    options_parser &add_long(
        const string &opt_name,
        const string &opt_desc_left,
        const string &opt_desc_right,
        bool has_arg = no_argument,
        callback_function_t callback = nullptr)
    {
        long_opts.emplace_back(
            opt_name,
            callback,
            opt_desc_left, opt_desc_right,
            has_arg);
        return *this;
    }

    bool has_option(char c)
    {
        return parsed_options.count(c);
    }

    bool has_option(const string &opt)
    {
        return parsed_long_options.count(opt);
    }

    void print_hint(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr,fmt,args);
        va_end(args);
        fprintf(stderr, "\n\nuse '-h' for help\n");
    }

    int parse(int argc, char *argv[])
    {
        int opt;
        string spec(":h");

        struct option long_options[long_opts.size()+1];
        for(size_t i = 0; i < long_opts.size(); i++) {
            long_options[i] = {
                .name = long_opts[i].name.data(),
                .has_arg = long_opts[i].has_arg,
                .flag = nullptr,
                .val = 0
            };
        }
        long_options[long_opts.size()] =
            {nullptr, 0, nullptr, 0};

        for(const auto &o : opts) {
            spec.push_back(o.first);
            if(o.second.has_arg) spec.push_back(':');
        }

        int opt_index;
        while (-1 != (opt = getopt_long(
            argc, argv, spec.data(),
            long_options, &opt_index)))
        {
            switch (opt) {
            case ':':
                fprintf(stderr,
                    "missing argument for option '%s'\n\n"
                    "use '-h' for help\n",
                    argv[optind-1]);
                return 1;
            case '?':
                fprintf(stderr,
                    "unknown option '%s'\n\n"
                    "use '-h' for help\n",
                    argv[optind-1]);
                return 1;
            case 'h': {
                size_t spacing = 0;
                for(const auto &o : opts) {
                    if(o.second.opt_desc_left.size() > spacing)
                        spacing = o.second.opt_desc_left.size();
                }
                for(const auto &o : long_opts) {
                    if(o.opt_desc_left.size() > spacing)
                        spacing = o.opt_desc_left.size();
                }
                spacing += 2;

                const char *basename_ptr = strrchr(argv[0], '/');
                printf("Usage:\n %s %s %s\n\n",
                       basename_ptr ? basename_ptr+1 : argv[0],
                       argv[1], usage_opts.data());

                printf(" -h%sdisplay this summary\n",
                       string(spacing - 2, ' ').data());

                for(const auto &o : opts) {
                    printf(" %s%s%s\n",
                        o.second.opt_desc_left.data(),
                        string(spacing - o.second.opt_desc_left.size(), ' ').data(),
                        o.second.opt_desc_right.data());
                }

                for(const auto &o : long_opts) {
                    printf(" %s%s%s\n",
                        o.opt_desc_left.data(),
                        string(spacing - o.opt_desc_left.size(), ' ').data(),
                        o.opt_desc_right.data());
                }

                return 1;
            }
            case 0: {
                auto &opt = long_opts[opt_index];
                parsed_long_options.emplace(opt.name);
                if(opt.callback)
                    opt.callback(opt.has_arg ? optarg : nullptr);
                break;
            }
            default:
                auto it = opts.find(opt);
                parsed_options.emplace(opt);
                if(it->second.callback) {
                    it->second.callback(
                        it->second.has_arg ? optarg : nullptr);
                }
                break;
            }
        }
        return 0;
    }
};

int encode(int argc, char *argv[])
{
    options_parser p("--key=key_path [opts]");
    AmIdentity identity;
    string key_path;

    identity.set_x5u_url("https://curl.haxx.se/ca/cacert.pem");
    identity.set_attestation(AmIdentity::AT_C);

    int verbose = 0;
    bool raw = false;
    if(p
        .add(
            'a',
            "-a A|B|C", "set attestation level (default: C)",true,
            [&identity,&p](const char *v) {
                switch(v[0]) {
                case 'A':
                    identity.set_attestation(AmIdentity::AT_A);
                    break;
                case 'B':
                    identity.set_attestation(AmIdentity::AT_B);
                    break;
                case 'C':
                    identity.set_attestation(AmIdentity::AT_C);
                    break;
                default:
                    p.print_hint("invalid attestation class '%c'", v[0]);
                    exit(1);
                }
             })
        .add(
            'v',
            "-v", "show intermediate data",false,
            [&verbose](const char *) {
            verbose++;
        })
        .add_long(
            "x5u",
            "--x5u=uri", "set uri (default: https://curl.haxx.se/ca/cacert.pem)", required_argument,
            [&identity](const char *value)
            {
                identity.set_x5u_url(value);
            })
        .add_long(
            "key",
            "--key=key_path", "set private key path for signing (mandatory)", required_argument,
            [&key_path](const char *value)
            {
                key_path = value;
            })
        .add_long(
            "ppt",
            "--ppt=shaken|div|div-o", "passport type (default: shaken)", required_argument,
            [&identity,&p](const char *value)
            {
                AmIdentity::PassportType t;
                if(!t.parse(value)) {
                    p.print_hint("invalid passport type '%s'", value);
                    exit(1);
                }
                identity.set_passport_type(t.get());
            })
        .add_long(
            "opt",
            "--opt=str", "opt claim for 'div-o' ppt", required_argument,
            [&identity](const char *value)
            {
                identity.set_opt(value);
            })
        .add_long(
            "orig_tn",
            "--orig_tn=number", "add orig tn", required_argument,
            [&identity](const char *value)
            {
                identity.add_orig_tn(value);
            })
        .add_long(
            "orig_uri",
            "--orig_uri=uri", "add orig uri", required_argument,
            [&identity](const char *value)
            {
                identity.add_orig_url(value);
            })
        .add_long(
            "dest_tn",
            "--dest_tn=number", "add dest tn", required_argument,
            [&identity](const char *value)
            {
                identity.add_dest_tn(value);
            })
        .add_long(
            "dest_uri",
            "--dest_uri=uri", "add dest uri", required_argument,
            [&identity](const char *value)
            {
                identity.add_dest_url(value);
            })
        .add_long(
            "div_tn",
            "--div_tn=number", "add div tn", required_argument,
            [&identity](const char *value)
            {
                identity.add_div_tn(value);
            })
        .add_long(
            "div_uri",
            "--div_uri=uri", "add div uri", required_argument,
            [&identity](const char *value)
            {
                identity.add_div_url(value);
            })
        .add_long(
            "raw",
            "--raw", "encode raw JWT", no_argument,
            [&raw](const char *)
            {
                raw = true;
            })
        .add_long(
            "claim",
            "--claim=key[:val[/{i,b}]]",
            "add custom claim (e.g null_key, str_key:str_val, int_key:42/i)",
            required_argument,
            [&identity](const char *claim_value)
            {
                std::string_view claim{claim_value}, key, value;
                if(auto p = claim.find(':'); std::string::npos != p) {
                    key = claim.substr(0, p);
                    value = claim.substr(p+1);
                } else {
                    key = claim;
                }

                auto &claim_arg = identity.get_payload()[std::string{key}];

                if(value.empty()) {
                    //add null claim
                    return;
                }

                if(auto p = value.find_last_of('/'); std::string::npos != p) {
                    auto type = value.substr(p+1);
                    if (type == "i") {
                        long i;
                        value = value.substr(0, p);
                        str2long(std::string{value}.data(), i);
                        claim_arg = i;
                        return;
                    } else if(type == "b") {
                        bool b;
                        value = value.substr(0, p);
                        str2bool(std::string{value}, b);
                        claim_arg = b;
                        return;
                    }
                }

                claim_arg = value.data();
            })
        .parse(argc, argv))
    {
        return 1;
    }

    if(key_path.empty()) {
        p.print_hint("missing mandatory option '--key'");
        return 1;
    }

    if(identity.get_passport_type() == AmIdentity::PassportType::ES256_PASSPORT_DIV_OPT
       && identity.get_opt().empty())
    {
        p.print_hint("missing mandatory option '--opt' for 'div-o' ppt");
        return 1;
    }

    std::unique_ptr<Botan::Private_Key> key;

    try {
        std::ifstream ifs;
        ifs.open(key_path);
        if(!ifs.is_open())
            throw Botan::Exception(std::string("failed to open: ") + key_path);

        Botan::DataSource_Stream datasource(ifs);

        key = Botan::PKCS8::load_key(datasource, std::string_view());

        auto identity_header = identity.generate(key.get(), raw);

        if(verbose) {
            printf("public key fingerprint (SHA-256):\n%s\n\n",
                   key->fingerprint_public().data());

            printf("header:\n%s\n\n",
                getFormattedJSON(identity.get_jwt_header()));

            printf("payload:\n%s\n\n",
                getFormattedJSON(identity.get_jwt_payload()));

            printf("output:\n");
        }

        cout << identity_header << endl;

        return 0;
    } catch(Botan::Exception &e) {
        cout << e.what() << endl;
    }

    return 1;
}

int decode(int argc, char *argv[])
{
    string in;
    bool raw = false;

    optind = 2;
    options_parser p("(-i FILE | INPUT)");
    if(p
        .add('i',"-i file","input file ('-' for stdin)",true,
             [&in](const char *value){ in = value; })
        .add_long(
            "raw",
            "--raw", "decode raw JWT", no_argument,
            [&raw](const char *)
            {
                raw = true;
            })
        .parse(argc, argv))
    {
        return 1;
    }

    if(in.empty()) {
        if (optind >= argc) {
            p.print_hint("no data to decode");
            return 1;
        }
        for(int i = optind; i < argc; i++) {
            in += argv[i];
        }
    } else if(in == "-") {
        in.clear();
        for(string l; getline(cin,l);)
            in += l;
    } else {
        std::ifstream f(in);
        if(!f.is_open()) {
            p.print_hint("failed to open: '%s'",in.data());
            return 1;
        }
        in.clear();
        for(string l; f;) {
            f >> l;
            in += l;
        }
    }

    if(in.empty()) {
        p.print_hint("empty input");
        return 1;
    }

    printf("input:\n%s\n\n", in.data());

    AmIdentity identity;
    int ret = identity.parse(in, raw);
    if(!ret) {
        int last_errcode;
        std::string last_error;
        last_errcode = identity.get_last_error(last_error);
        printf("error: %d %s\n",
               last_errcode, last_error.data());
        return 1;
    }

    printf("header:\n%s\n\n",
        getFormattedJSON(identity.get_jwt_header()));

    printf("payload:\n%s\n\n",
        getFormattedJSON(identity.get_jwt_payload()));

    return 0;
}

int verify(int argc, char *argv[])
{
    string in;
    AmIdentity identity;
    string cert_path;
    bool raw = false;

    optind = 2;
    options_parser p("--cert=cert_path (-i FILE | INPUT)");
    if(p
        .add('i',"-i file","input file ('-' for stdin)",true,
             [&in](const char *value){ in = value; })
        .add_long(
            "cert",
            "--cert=cert_path", "set certificate path to verify signature (mandatory)", required_argument,
            [&cert_path](const char *value)
            {
                cert_path = value;
            })
        .add_long(
            "raw",
            "--raw", "verify raw JWT", no_argument,
            [&raw](const char *)
            {
                raw = true;
            })
        .parse(argc, argv))
    {
        return 1;
    }

    if(in.empty()) {
        if (optind >= argc) {
            p.print_hint("no data to decode");
            return 1;
        }
        for(int i = optind; i < argc; i++) {
            in += argv[i];
        }
    } else if(in == "-") {
        in.clear();
        for(string l; getline(cin,l);)
            in += l;
    } else {
        std::ifstream f(in);
        if(!f.is_open()) {
            p.print_hint("failed to open: '%s'",in.data());
            return 1;
        }
        in.clear();
        for(string l; f;) {
            f >> l;
            in += l;
        }
    }

    if(in.empty()) {
        p.print_hint("empty input");
        return 1;
    }

    if(cert_path.empty()) {
        p.print_hint("missing mandatory option '--cert'");
        return 1;
    }

    printf("input:\n%s\n\n", in.data());

    try {
        int last_errcode;
        std::string last_error;

        AmIdentity identity;

        Botan::X509_Certificate crt(cert_path);

        int ret = identity.parse(in, raw);
        if(!ret) {
            last_errcode = identity.get_last_error(last_error);
            printf("parse error: %d %s\n",
                   last_errcode, last_error.data());
            return 1;
        }

        ret = identity.verify(
            crt.subject_public_key().get(),
            time(0) - identity.get_created() + 2);
        if(!ret) {
            last_errcode = identity.get_last_error(last_error);
            printf("verify error: %d %s\n",
                   last_errcode, last_error.data());
            return 1;
        }

        printf("verified with certificate (%s)\n",
               crt.issuer_dn().to_string().data());

        return 0;
    } catch(Botan::Exception &e) {
        cout << e.what() << endl;
    }

    return 1;
}

static void serializeCert(AmArg &info, const Botan::X509_Certificate &cert)
{
    info["subject"] = cert.subject_dn().to_string();
    info["issuer"] = cert.issuer_dn().to_string();
    info["fingerprint_sha1"] = cert.fingerprint("SHA-1");

    if(auto i = cert.subject_info("X509.Certificate.serial"); !i.empty())
        info["serial"] = *i.begin();
    if(auto i = cert.subject_info("X509v3.SubjectKeyIdentifier"); !i.empty())
        info["subject_key_identifier"] = *i.begin();
    if(auto i = cert.subject_info("X509v3.AuthorityKeyIdentifier"); !i.empty())
        info["authority_key_identifier"] = *i.begin();

    if(const auto *tn_auth_list =
        cert.v3_extensions().get_extension_object_as<Botan::Cert_Extension::TNAuthList>())
    {
        AmArg &tn_list = info["tn_auth_list"];
        for(const auto &e:  tn_auth_list->entries()) {
            tn_list.push(AmArg());
            auto &tn = tn_list.back();
            tn.assertStruct();
            switch(e.type()) {
            case Botan::Cert_Extension::TNAuthList::Entry::ServiceProviderCode:
                tn["spc"] = e.service_provider_code();
                break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumberRange: {
                auto &ranges = tn["range"];
                ranges.assertArray();
                for(auto &range : e.telephone_number_range()) {
                    ranges.push(AmArg());
                    auto &r = ranges.back();
                    r["start"] = range.start.value();
                    r["count"] = range.count;
                }
            } break;
            case Botan::Cert_Extension::TNAuthList::Entry::TelephoneNumber:
                tn["one"] = e.telephone_number();
                break;
            }
        }
    }
}

int cert_decode(int argc, char *argv[])
{
    string in;

    optind = 2;
    options_parser p("(-i FILE | INPUT)");
    if(p
        .add('i',"-i file","input file ('-' for stdin)",true,
             [&in](const char *value){ in = value; })
        .parse(argc, argv))
    {
        return 1;
    }

    if(in.empty()) {
        if (optind >= argc) {
            p.print_hint("no data to decode");
            return 1;
        }
        for(int i = optind; i < argc; i++) {
            in += argv[i];
        }
    } else if(in == "-") {
        in.clear();
        for(string l; getline(cin,l);)
            in += l;
    } else {
        std::ifstream f(in);
        if(!f.is_open()) {
            p.print_hint("failed to open: '%s'",in.data());
            return 1;
        }
        in.clear();

        std::ostringstream sstr;
        sstr << f.rdbuf();
        in = sstr.str();
    }

    if(in.empty()) {
        p.print_hint("empty input");
        return 1;
    }

    Botan::DataSource_Memory data_source(in);
    while(!data_source.end_of_data()) {
        try {
            AmArg info;
            std::unique_ptr<Botan::X509_Certificate> cert(
                new Botan::X509_Certificate(data_source));

            serializeCert(info, *cert);

            printf("%s\n", getFormattedJSON(arg2json(info).data()));
        } catch(Botan::Exception &e) {
            //throw e;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    register_stderr_facility();
    set_stderr_log_level(L_DBG);

    return commands_dispatcher()
        .add("encode", encode)
        .add("decode", decode)
        .add("verify", verify)
        .add("decode_TNAuthList_cert", cert_decode)
        .add("version",[](int argc, char *argv[]) -> int {
            printf("%s\n", SEMS_VERSION);
            return 0;
        })
        .dispatch(argc, argv);
}
