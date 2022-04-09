#pragma once

namespace Parameters
{
class Flag // could be a template
{
public:
	explicit Flag( char identifier, float value ) : m_value( value ), m_identifier( identifier ){};
	virtual ~Flag() = default;

	virtual float getValueFromIdentifier( const char identifier ) const = 0;
	virtual float getDefault() const									= 0;
	virtual float getValue() const
	{
		return m_value;
	}

	virtual char getIdentifier() const
	{
		return m_identifier;
	}

protected:
	float m_value;
	char m_identifier;
};
} // namespace Parameters
