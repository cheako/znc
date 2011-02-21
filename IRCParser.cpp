/*
 * Copyright (C) 2004-2011  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "IRCParser.h"
#include "Socket.h"

bool CIRCParser::RegisterCommand(const CString& sCmd, CmdFunc pCallback) {
	// Sanity check
	if (pCallback == NULL)
		return false;
	// Force upper-case
	if (sCmd.AsUpper() != sCmd)
		return false;
	// Disallow numerics
	if (CString(sCmd.ToUInt()) == sCmd)
		return false;
	// Spaces are a really bad idea
	if (sCmd.find(' ') != CString::npos)
		return false;
	// We don't let stuff silently overwrite commands
	if (m_mCommands.find(sCmd) != m_mCommands.end())
		return false;
	m_mCommands[sCmd] = pCallback;
	return true;
}

CIRCParser::CmdFunc CIRCParser::FindCommand(const CString& sCmd) const {
	map<CString, CmdFunc>::const_iterator it;
	it = m_mCommands.find(sCmd.AsUpper());
	if (it == m_mCommands.end())
		return NULL;
	return it->second;
}

bool CIRCParser::RegisterRaw(unsigned int uiNum, RawFunc pCallback) {
	if (uiNum < 1 || uiNum > 999)
		return false;
	if (pCallback == NULL)
		return false;
	if (m_mRaws.find(uiNum) != m_mRaws.end())
		return false;
	m_mRaws[uiNum] = pCallback;
	return true;
}

CIRCParser::RawFunc CIRCParser::FindRaw(unsigned int uiNum) const {
	map<unsigned int, RawFunc>::const_iterator it;
	it = m_mRaws.find(uiNum);
	if (it == m_mRaws.end())
		return NULL;
	return it->second;
}

bool CIRCParser::ParseLine(CZNCSock* pSock, const CString& sLine) const {
	CString sCmd = sLine.Token(0);
	CString sSource;
	CString sArgs;

	// Do we have a source?
	if (sCmd.Left(1) == ":") {
		sSource = sCmd.substr(1);
		sCmd = sLine.Token(1);
		sArgs = sLine.Token(2, true);
	} else {
		sArgs = sLine.Token(1, true);
	}

	if (sCmd.length() == 3 && isdigit(sCmd[0]) && isdigit(sCmd[1]) && isdigit(sCmd[2])) {
		// We got a numeric!
		unsigned int uRaw = sCmd.ToUInt();
		CString sNick = sArgs.Token(0);
		sArgs = sArgs.Token(1, true);

		RawFunc pFunc = FindRaw(uRaw);
		if (!pFunc)
			return false;
		(pSock->*pFunc)(sSource, uRaw, sNick, sArgs);
	} else {
		// "Normal" IRC command
		CmdFunc pFunc = FindCommand(sCmd);
		if (!pFunc)
			return false;

		(pSock->*pFunc)(sSource, sCmd, sArgs);
	}

	return true;
}
