#pragma once
#include "flag.hpp"

namespace Parameters
{
class RiskFlag : public Flag
{
public:
	explicit RiskFlag( char identifier );
	float getValueFromIdentifier( const char identifier ) const override;
	float getDefault() const override;
};

class AttackType : public Flag
{
public:
	explicit AttackType( char identifier );
	float getValueFromIdentifier( const char identifier ) const override;
	float getDefault() const override;
};

class RangeFlag : public Flag
{
public:
	explicit RangeFlag( char identifier );
	float getValueFromIdentifier( const char identifier ) const override;
	float getDefault() const override;
};

class AccessFlag : public Flag
{
public:
	explicit AccessFlag( char identifier );
	float getValueFromIdentifier( const char identifier ) const override;
	float getDefault() const override;
};

class AvailabilityFlag : public Flag
{
public:
	explicit AvailabilityFlag( char identifier );
	float getValueFromIdentifier( const char identifier ) const override;
	float getDefault() const override;
};
} // namespace Parameters