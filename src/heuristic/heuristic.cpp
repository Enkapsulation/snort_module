#include <iostream>
#include <memory>

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"

#include "heuristic.hpp"
#include "heuristic_types.hpp"

using namespace snort;

//-------------------------------------------------------------------------
// implementation stuff
//-------------------------------------------------------------------------
void Heuristic::heuristic_show_config( const std::shared_ptr< HeuristicConfig >& ) const
{
	if( config )
	{
		// TO DO??
		return;
	}

	ConfigLogger::log_option( "hosts" );
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------
Heuristic::Heuristic( HeuristicModule* mod ) : config( mod->get_config() ) {}

Heuristic::~Heuristic() = default;

void Heuristic::show( const SnortConfig* ) const
{
	if( config )
	{
		heuristic_show_config( config );
	}
}

void Heuristic::eval( Packet* packet )
{
	std::cout << "Hello World from -> " << packet->is_icmp() << std::endl;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------
static Module* mod_ctor()
{
	return new HeuristicModule;
}

static void mod_dtor( Module* module )
{
	delete module;
}

static Inspector* heu_ctor( Module* module )
{
	return new Heuristic( ( HeuristicModule* )module );
}

static void heu_dtor( Inspector* inspector )
{
	delete inspector;
}

static const InspectApi as_api = {
	{ PT_INSPECTOR,
	  sizeof( InspectApi ),
	  INSAPI_VERSION,
	  0,
	  API_RESERVED,
	  API_OPTIONS,
	  s_name,
	  s_help,
	  mod_ctor,
	  mod_dtor },
	IT_NETWORK,
	PROTO_BIT__ARP,
	nullptr, // buffers
	nullptr, // service
	nullptr, // pinit
	nullptr, // pterm
	nullptr, // tinit
	nullptr, // tterm
	heu_ctor,
	heu_dtor,
	nullptr, // ssn
	nullptr, // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_heuristic[] =
#endif
	{ &as_api.base, nullptr };