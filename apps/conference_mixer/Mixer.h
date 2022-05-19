#pragma once

#include "Rings.h"
#include "ConferenceChannel.h"
#include "ConferenceMedia.h"
#include "MultiPartyMixer.h"
#include "ampi/MixerAPI.h"

#include "AmThread.h"
#include "atomic_types.h"
#include <sip/resolver.h>
#include "SampleArray.h"
#include "AmEventFdQueue.h"
#include "AmEventQueue.h"
#include "AmAudio.h"
#include "AmRtpStream.h"
#include "AmSession.h"

#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include <sstream>
#include <vector>

using std::deque;
using std::map;
using std::string;
using std::vector;

using std::string;
using std::unordered_map;
using std::shared_ptr;


#define MIXER_DEFAULT_LISTEN_ADDRESS      "localhost"
#define MIXER_DEFAULT_PORT                5002
#define MIXER_DISPATCHER_MAX_EPOLL_EVENT  256
#define TIMER_INTERVAL_SEC                1

#ifdef RORPP_PLC
#include "LowcFE.h"
#endif

#define MIXER_EVENT_QUEUE "mixer"
