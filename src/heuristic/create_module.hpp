#pragma once
#include <memory>
#include <string_view>

class HeuristicModule;

namespace Create
{
static std::unique_ptr< HeuristicModule > g_heuristicModule;
} // namespace Create