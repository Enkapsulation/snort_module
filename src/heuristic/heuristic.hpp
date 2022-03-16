#ifndef __HEURISTIC_H__
#define __HEURISTIC_H__

#include <math.h>
#include <memory>

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

THREAD_LOCAL const Trace* heu_trace = nullptr;

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Heuristic : public Inspector
{
public:
	Heuristic( HeuristicModule* );
	virtual ~Heuristic();

	void show( const SnortConfig* ) const override;
	void eval( Packet* ) override;

private:
	void heuristic_show_config( const std::shared_ptr< HeuristicConfig >& ) const;

	std::shared_ptr< HeuristicConfig > config;
};

#endif /* __HEURISTIC_H__ */
