#include "create_module.hpp"
#include <memory>

#include "detection/detection_engine.h"
#include "heuristic_module.hpp"

using namespace snort;
using namespace Create;

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------
static Module* mod_ctor()
{
	g_heuristicModule = std::make_unique< HeuristicModule >();
	return g_heuristicModule.get();
}

static void mod_dtor( Module* )
{
	g_heuristicModule.reset();
}

static Inspector* heu_ctor( Module* module )
{
	return g_heuristicModule->getInspector();
}

static void heu_dtor( Inspector* ) {}

static const InspectApi as_api = {
	{ PT_INSPECTOR,
	  sizeof( InspectApi ),
	  INSAPI_VERSION,
	  0,
	  API_RESERVED,
	  API_OPTIONS,
	  HeuristicModule::getName().data(),
	  HeuristicModule::getHelp().data(),
	  mod_ctor,
	  mod_dtor },
	IT_NETWORK,
	PROTO_BIT__ALL,
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

// #ifdef BUILDING_SO
// SO_PUBLIC const BaseApi* snort_plugins[] =
// #else
// const BaseApi* nin_heuristic[] =
// #endif
// 	{ &as_api.base, nullptr };

SO_PUBLIC const BaseApi* snort_plugins[] = { &as_api.base, nullptr };
