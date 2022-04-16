#pragma once
#include "flag.hpp"
#include <string>
namespace Parameters
{
bool setFlagsMaps( std::string flagIdentifier, std::string identifier, float value );

class DangerousFlag : public Flag
{
public:
	explicit DangerousFlag( std::string identifier );
	float getValueFromIdentifier( std::string identifier ) const override;
	float getDefault() const override;
};

class AttackType : public Flag
{
public:
	explicit AttackType( std::string identifier );
	float getValueFromIdentifier( std::string identifier ) const override;
	float getDefault() const override;
};

class RangeFlag : public Flag
{
public:
	explicit RangeFlag( std::string identifier );
	float getValueFromIdentifier( std::string identifier ) const override;
	float getDefault() const override;
};

class AccessFlag : public Flag
{
public:
	explicit AccessFlag( std::string identifier );
	float getValueFromIdentifier( std::string identifier ) const override;
	float getDefault() const override;
};

class AvailabilityFlag : public Flag
{
public:
	explicit AvailabilityFlag( std::string identifier );
	float getValueFromIdentifier( std::string identifier ) const override;
	float getDefault() const override;
};
} // namespace Parameters