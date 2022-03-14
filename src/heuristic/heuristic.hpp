#ifndef __HEURISTIC_H__
#define __HEURISTIC_H__

#include <math.h>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "heuristic_types.hpp"
#include "heuristic_module.hpp"

using namespace snort;

THREAD_LOCAL const Trace *heu_trace = nullptr;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Heuristic : public Inspector
{
private:
    HeuristicConfig* config;
    void heuristic_show_config(const HeuristicConfig*) const;

public:
    Heuristic(HeuristicModule*);
    ~Heuristic() override;

    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
};

#endif /* __HEURISTIC_H__ */
