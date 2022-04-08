#pragma once
#include "flag.hpp"

namespace Parameters
{
class RiskFlag : public Flag
{
public:
	float getValueFromIdentifier() const override;
};

class AttackType : public Flag
{
public:
	float getValueFromIdentifier() const override;
};

class RangeFLag : public Flag
{
public:
	float getValueFromIdentifier() const override;
};

class AccessFlag : public Flag
{
public:
	float getValueFromIdentifier() const override;
};

class AvailabilityFlag : public Flag
{
public:
	float getValueFromIdentifier() const override;
};
} // namespace Parameters