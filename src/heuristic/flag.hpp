#pragma once

namespace Parameters
{
class Flag
{
public:
	explicit Flag( char identifier, float value ) : m_identifier( identifier ), m_value( value ){};
	virtual ~Flag() = default;

	virtual float getValueFromIdentifier() const = 0; // could be a template

protected:
	char m_identifier;
	float m_value;
};
} // namespace Parameters
