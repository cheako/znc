/*
 * Copyright (C) 2004-2011  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef _IRCPARSER_H
#define _IRCPARSER_H

#include "zncconfig.h"
#include "ZNCString.h"

class CZNCSock;

class CIRCParser {
public:
	typedef void (CZNCSock::*CmdFunc)(const CString& sSource, const CString& sCmd, const CString& sArgs);
	typedef void (CZNCSock::*RawFunc)(const CString& sServer, unsigned int uiRaw, const CString& sNick, const CString& sArgs);

	CIRCParser() : m_mCommands(), m_mRaws() {}

	bool RegisterCommand(const CString& sCmd, CmdFunc pCallback);
	CmdFunc FindCommand(const CString& sCmd) const;

	bool RegisterRaw(unsigned int uiNum, RawFunc pCallback);
	RawFunc FindRaw(unsigned int uiNum) const;

	bool ParseLine(CZNCSock* pSock, const CString& sLine) const;

private:
	map<CString, CmdFunc>      m_mCommands;
	map<unsigned int, RawFunc> m_mRaws;
};

#endif // !_IRCPARSER_H
