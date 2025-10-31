#include "AmApi.h"

class CoreUnitFactory : public AmPluginFactory {
    CoreUnitFactory(const string &name)
        : AmPluginFactory(name)
    {
    }
    ~CoreUnitFactory() {}

  public:
    DECLARE_FACTORY_INSTANCE(CoreUnitFactory);

    int onLoad() override { return 0; }
};


EXPORT_PLUGIN_FACTORY(CoreUnitFactory)
DEFINE_FACTORY_INSTANCE(CoreUnitFactory, "core_unit");
