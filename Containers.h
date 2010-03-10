/*
 * Copyright (C) 2004-2010  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef _CONTAINERS_H
#define _CONTAINERS_H

#include <map>
#include <time.h>

using std::map;

template<typename T, typename container>
class TCacheImpl {
public:
	typedef container                               container_type;
	typedef typename container_type::size_type      size_type;
	typedef typename container_type::value_type     value_type;
	typedef typename container_type::iterator       iterator;
	typedef typename container_type::const_iterator const_iterator;

	TCacheImpl(unsigned int uTTL = 5) : m_uTTL(uTTL) {}

	unsigned int GetTTL() const { return m_uTTL; }
	void SetTTL(unsigned int i) { m_uTTL = i; }

	bool HasItem(const T& key) {
		return find(key) != end();
	}

	pair<const_iterator, bool> insert(const value_type& val, unsigned int uTTL) {
		insertCache(valueToKey(val), uTTL);
		return m_mValues.insert(val);
	}

	pair<const_iterator, bool> insert(const T& key) {
		insertCache(key, m_uTTL);
		return m_mValues.insert(key);
	}

	size_type erase(const T& key) {
		m_mExpires.erase(key);
		return m_mValues.erase(key);
	}

	void clear() {
		m_mExpires.clear();
		m_mValues.clear();
	}

	const_iterator find(const T& key) {
		Cleanup();
		return m_mValues.find(key);
	}

	const_iterator begin() const {
		return m_mValues.begin();
	}

	const_iterator end() const {
		return m_mValues.end();
	}

	void Cleanup() {
		time_t now = time(NULL);
		typename map_type::iterator it = m_mExpires.begin();

		while (it != m_mExpires.end()) {
			if (it->second > now) {
				++it;
				continue;
			}

			m_mValues.erase(it->first);
			m_mExpires.erase(it++);
		}
	}

protected:
	virtual const T& valueToKey(const value_type& val) = 0;

	void insertCache(const T& key, unsigned int uTTL) {
		time_t expire = time(NULL) + uTTL;

		m_mExpires.insert(make_pair(key, expire));
	}

private:
	typedef map<T, time_t> map_type;

	map_type       m_mExpires;
	container_type m_mValues;
	unsigned int   m_uTTL;
};

template<typename T>
class TCacheSet : public TCacheImpl<T, set<T> > {
	typedef TCacheImpl<T, set<T> > impl;

public:
	TCacheSet(unsigned int uTTL = 5) : impl(uTTL) {}

private:
	const T& valueToKey(const typename impl::value_type& val) {
		return val;
	}
};

template<typename K, typename V>
class TCacheMap : public TCacheImpl<K, map<K, V> > {
	typedef TCacheImpl<K, map<K, V> > impl;

public:
	TCacheMap(unsigned int uTTL = 5) : impl(uTTL) {}

private:
	const K& valueToKey(const typename impl::value_type& val) {
		return val.first;
	}
};

#endif // !_CONTAINERS_H
