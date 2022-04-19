#include "ObjectsCounter.h"

#include "AmSession.h"
#include "AmRtpStream.h"
#include "AmB2BMedia.h"

#include "sip/sip_trans.h"

void init_core_objects_counters()
{
    ObjCounterInit(AmRtpStream);
    ObjCounterInit(AmMediaTransport);
    ObjCounterInit(AmStreamConnection);
    ObjCounterInit(AmB2BMedia);

    ObjCounterInit(AmSession);
    ObjCounterInit(AmEvent);

    ObjCounterInit(sip_trans);
    ObjCounterInit(dns_base_entry);
    ObjCounterInit(base_timer);
}
