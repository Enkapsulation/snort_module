
#pragma once
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

class CSVRow
{
public:
	std::string operator[]( std::size_t index ) const;
	std::size_t size() const;

	void readNextRow( std::istream& str );

private:
	std::string m_line;
	std::vector< int > m_data;
};

class CSVIterator
{
public:
	using iterator_category = std::input_iterator_tag;
	using value_type		= CSVRow;
	using difference_type	= std::size_t;
	using pointer			= CSVRow*;
	using reference			= CSVRow&;

	CSVIterator( std::istream& str );
	CSVIterator();

	CSVIterator& operator++();
	CSVIterator operator++( int );

	CSVRow const& operator*() const;
	CSVRow const* operator->() const;

	bool operator==( CSVIterator const& rhs );
	bool operator!=( CSVIterator const& rhs );

private:
	std::istream* m_str;
	CSVRow m_row;
};

class CSVRange
{
	std::istream& stream;

public:
	explicit CSVRange( std::istream& str );

	CSVIterator begin() const;
	CSVIterator end() const;
};