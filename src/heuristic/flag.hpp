#pragma once

#include <string>
namespace Parameters
{
class Flag // could be a template
{
public:
	explicit Flag( std::string identifier, float value ) : m_value( value ), m_identifier( identifier ){};
	virtual ~Flag() = default;

	virtual float getValueFromIdentifier( std::string identifier ) const = 0;
	virtual float getDefault() const									 = 0;
	virtual float getValue() const
	{
		return m_value;
	}

	virtual std::string getIdentifier() const
	{
		return m_identifier;
	}

protected:
	float m_value;
	std::string m_identifier;
};
} // namespace Parameters
