#pragma once
#include "flag.hpp"

namespace Parameters
{
class RiskFlag : public Flag
{
public:
	float getValueFromIdentifier() const override;
};
} // namespace Parameters