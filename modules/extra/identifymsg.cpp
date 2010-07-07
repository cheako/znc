/*
 * Copyright (C) 2004-2010  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "Chan.h"
#include "User.h"
#include "Client.h"
#include "IRCSock.h"
#include "Modules.h"

class CIdMsgMod : public CGlobalModule {
public:
	GLOBALMODCONSTRUCTOR(CIdMsgMod) {}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
		return true;
	}

	virtual ~CIdMsgMod() {}

	virtual bool OnServerCapAvailable(const CString& sCap) {
		return sCap == "identify-msg";
	}

/*	virtual void OnServerCapAccepted(const CString& sCap) {
		if (sCap == "identify-msg") {
			// Do nothing in this module here
		}
	}*/

	virtual void OnClientCapLs(SCString& ssCaps) {
		ssCaps.insert("identify-msg");
	}

	virtual bool IsClientCapSupported(const CString& sCap, bool bState) {
		return sCap == "identify-msg";
	}

/*	virtual void OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) {
		if (sCap == "identify-msg") {
			// Do nothing in this module here
		}
	}*/

	CString ProcessMessage(const CString& sMessage, bool bServer, bool bClient) {
		if (bServer) {
			if (!bClient) {
				CString sRes = sMessage;
				sRes.TrimPrefix("+") || sRes.TrimPrefix("-");
				return sRes;
			}
		} else {
			if (bClient) {
				// Server didn't send us this info, assume that noone is identified.
				return "-" + sMessage;
			}
		}
		return sMessage;
	}

	virtual EModRet OnPrivMsg(CNick& Nick, CString& sMessage) {
		bool bServer = GetUser()->GetIRCSock()->IsCapAccepted("identify-msg");
		if (GetUser()->GetModules().OnPrivMsg(Nick, sMessage)) {
			// User module halted. Do not forward message to clients.
			return HALT;
		}
		for (unsigned int a = 0; a < GetUser()->GetClients().size(); ++a) {
			CClient* Client = GetUser()->GetClients()[a];
			Client->PutClient(":" + Nick.GetNickMask() + " PRIVMSG " + GetUser()->GetCurNick() + " :" +
					ProcessMessage(sMessage, bServer, Client->IsCapEnabled("identify-msg")));
		}
		if (!GetUser()->IsUserAttached()) {
			// If the user is detached, add to the buffer
			GetUser()->AddQueryBuffer(":" + Nick.GetNickMask() + " PRIVMSG ",
					" :" + GetUser()->AddTimestamp(sMessage));
		}
		return HALT;
	}

	virtual EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage) {
		bool bServer = GetUser()->GetIRCSock()->IsCapAccepted("identify-msg");
		if (GetUser()->GetModules().OnChanMsg(Nick, Channel, sMessage)) {
			// User module halted. Do not forward message to clients.
			return HALT;
		}
		for (unsigned int a = 0; a < GetUser()->GetClients().size(); ++a) {
			CClient* Client = GetUser()->GetClients()[a];
			Client->PutClient(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() + " :" +
					ProcessMessage(sMessage, bServer, Client->IsCapEnabled("identify-msg")));
		}
		if (Channel.KeepBuffer() || !GetUser()->IsUserAttached() || Channel.IsDetached()) {
			Channel.AddBuffer(":" + Nick.GetNickMask() + " PRIVMSG " + Channel.GetName() +
					" :" + GetUser()->AddTimestamp(sMessage));
		}
		return HALT;
	}

	virtual EModRet OnPrivNotice(CNick& Nick, CString& sMessage) {
		bool bServer = GetUser()->GetIRCSock()->IsCapAccepted("identify-msg");
		if (GetUser()->GetModules().OnPrivNotice(Nick, sMessage)) {
			// User module halted. Do not forward message to clients.
			return HALT;
		}
		for (unsigned int a = 0; a < GetUser()->GetClients().size(); ++a) {
			CClient* Client = GetUser()->GetClients()[a];
			Client->PutClient(":" + Nick.GetNickMask() + " NOTICE " + GetUser()->GetCurNick() + " :" +
					ProcessMessage(sMessage, bServer, Client->IsCapEnabled("identify-msg")));
		}
		if (!GetUser()->IsUserAttached()) {
			// If the user is detached, add to the buffer
			GetUser()->AddQueryBuffer(":" + Nick.GetNickMask() + " NOTICE ",
					" :" + GetUser()->AddTimestamp(sMessage));
		}
		return HALT;
	}

	virtual EModRet OnChanNotice(CNick& Nick, CChan& Channel, CString& sMessage) {
		bool bServer = GetUser()->GetIRCSock()->IsCapAccepted("identify-msg");
		if (GetUser()->GetModules().OnChanNotice(Nick, Channel, sMessage)) {
			// User module halted. Do not forward message to clients.
			return HALT;
		}
		for (unsigned int a = 0; a < GetUser()->GetClients().size(); ++a) {
			CClient* Client = GetUser()->GetClients()[a];
			Client->PutClient(":" + Nick.GetNickMask() + " NOTICE " + Channel.GetName() + " :" +
					ProcessMessage(sMessage, bServer, Client->IsCapEnabled("identify-msg")));
		}
		if (Channel.KeepBuffer() || !GetUser()->IsUserAttached() || Channel.IsDetached()) {
			Channel.AddBuffer(":" + Nick.GetNickMask() + " NOTICE " + Channel.GetName() +
					" :" + GetUser()->AddTimestamp(sMessage));
		}
		return HALT;
	}
};

GLOBALMODULEDEFS(CIdMsgMod, "Adds support for identify-msg capability")

