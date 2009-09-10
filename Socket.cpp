/*
 * Copyright (C) 2004-2009  See the AUTHORS file for details.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#include "Socket.h"
#ifdef HAVE_ARES
#include <ares.h>
#endif

#ifdef HAVE_ARES
struct DNSLookup {
	bool bSocketDead;
	bool bLookupDone;
	// When both of the above are true, this struct can be freed

	// Query
	CString sHost;
	CSSockAddr::EAFRequire family;

	// Result
	int ares_status;
	CSSockAddr addr;
};

static ares_channel& GetAres() {
	static ares_channel m_ares;
	return m_ares;
}

#warning This is ugly :(
static ev_check ares_check;
static ev_prepare ares_prep;
static ev_timer ares_timer;

static void AresTimeoutCheck(EV_P_ ev_check *, int)
{
	// This makes c-ares process timeouts
	ares_process_fd(GetAres(), ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	// We only use that timer to wake up the event loop, it doesn't actually
	// ever fire an event
	ev_timer_stop(EV_DEFAULT_UC_ &ares_timer);
}

static void AresTimeoutPrepare(EV_P_ ev_prepare *, int)
{
	struct timeval tv;
	struct timeval *p_tv;

	p_tv = ares_timeout(GetAres(), NULL, &tv);

	// If this is NULL, ares doesn't wait on any timeouts and since our
	// timer is already stopped: Nothing to do
	if (!p_tv)
		return;

	// Else we start a timer so that the event loop will wake us up.
	// We sleep a little longer than we'd have to by "rounding" the timeout
	// up to the next full second.
	ev_timer_set(&ares_timer, tv.tv_sec + 1, 0);
	ev_timer_start(EV_DEFAULT_UC_ &ares_timer);
}

static void AresSocketCallback(void *data, ares_socket_t fd, int readable, int writeable);
#endif

CZNCSock::~CZNCSock() {
#ifdef HAVE_ARES
	if (m_dns_lookup) {
		m_dns_lookup->bSocketDead = true;
		if (m_dns_lookup->bLookupDone)
			delete m_dns_lookup;
		m_dns_lookup = NULL;
	}
#endif
}

CSockManager::CSockManager() : TSocketManager<CZNCSock>() {
#ifdef HAVE_ARES
	struct ares_options opts;
	memset(&opts, 0, sizeof(opts));

	opts.sock_state_cb = AresSocketCallback;
	opts.sock_state_cb_data = this;

	int i = ares_init_options(&GetAres(), &opts, ARES_OPT_SOCK_STATE_CB);
	if (i != ARES_SUCCESS) {
		CUtils::PrintError("Could not initialize c-ares: " + CString(ares_strerror(i)));
		exit(-1);
	}
	DEBUG("Successfully initialized c-ares");

	ev_check_init(&ares_check, AresTimeoutCheck);
	ev_check_start(EV_DEFAULT_UC_ &ares_check);

	ev_prepare_init(&ares_prep, AresTimeoutPrepare);
	// Make sure this is executed after TSocketManager::Prepare
	ev_set_priority(&ares_prep, EV_MINPRI);
	ev_prepare_start(EV_DEFAULT_UC_ &ares_prep);

	ev_timer_init(&ares_timer, NULL, 0, 0);
#endif
}

CSockManager::~CSockManager() {
#ifdef HAVE_ARES
	ares_destroy(GetAres());
	ev_check_stop(EV_DEFAULT_UC_ &ares_check);
	ev_prepare_stop(EV_DEFAULT_UC_ &ares_prep);
	ev_timer_stop(EV_DEFAULT_UC_ &ares_timer);
#endif
}

#ifdef HAVE_ARES
void CZNCSock::ares_callback(void *lookup, int status, int timeout, struct hostent *h) {
	struct DNSLookup *p = (struct DNSLookup *) lookup;
	p->bLookupDone = true;

	DEBUG("DNS lookup done for " << p->sHost);
	if (p->bSocketDead) {
		delete p;
		return;
	}

	p->ares_status = status;
	if (!h) {
#ifdef HAVE_IPV6
		if (p->family == CSSockAddr::RAF_ANY) {
			// Try an AAAA lookup
			p->family = CSSockAddr::RAF_INET6;
			DEBUG("Retrying with AAAA");
			p->bLookupDone = false;
			ares_gethostbyname(GetAres(), p->sHost.c_str(), p->family,
					ares_callback, p);
			return;
		}
#endif
		if (status == ARES_SUCCESS)
			p->ares_status = ARES_ENOTIMP;
		return;
	}

	if (h->h_addrtype == AF_INET && h->h_length == sizeof(in_addr)) {
		memcpy(p->addr.GetAddr(), h->h_addr_list[0], sizeof(in_addr));
		p->addr.SetIPv6(false);
	}
#ifdef HAVE_IPV6
	else if (h->h_addrtype == AF_INET6 && h->h_length == sizeof(in6_addr)) {
		memcpy(p->addr.GetAddr6(), h->h_addr_list[0], sizeof(in6_addr));
		p->addr.SetIPv6(true);
	}
#endif
	else
		DEBUG(__PRETTY_FUNCTION__ << ": Got unknown address with length " << h->h_length);
}

int CZNCSock::GetAddrInfo(const CS_STRING &sHostname, CSSockAddr &csSockAddr) {
	// If this is an ip address, no lookup is necessary
#ifdef HAVE_IPV6
	if (inet_pton(AF_INET6, sHostname.c_str(), csSockAddr.GetAddr6()) > 0) {
		csSockAddr.SetIPv6(true);
		SetIPv6(true);
		return 0;
	}
#endif
	if (inet_pton(AF_INET, sHostname.c_str(), csSockAddr.GetAddr()) > 0) {
		csSockAddr.SetIPv6(false);
		SetIPv6(false);
		return 0;
	}

	if (!m_dns_lookup) {
		DEBUG("New dns lookup for " << sHostname);

		m_dns_lookup = new struct DNSLookup;
		m_dns_lookup->bSocketDead = false;
		m_dns_lookup->bLookupDone = false;
		m_dns_lookup->sHost = sHostname;
		m_dns_lookup->ares_status = 0;
		m_dns_lookup->family = csSockAddr.GetAFRequire();

		CSSockAddr::EAFRequire family = csSockAddr.GetAFRequire();
		if (family == CSSockAddr::RAF_ANY) {
			// post-1.6.0 c-ares (=current CVS versions) support
			// lookups with AF_UNSPEC which means it first tries an
			// AAAA lookup and then fails back to an A lookup.
			// Older versions (= any version out there) just
			// generate an "address family not supported" error
			// message if you feed them, so we can't use this nice
			// feature for now.
			family = CSSockAddr::RAF_INET;
		}
		ares_gethostbyname(GetAres(), sHostname.c_str(), family,
				ares_callback, m_dns_lookup);
	}

	if (m_dns_lookup->sHost != sHostname)
		// This *cannot* happen
		DEBUG(__PRETTY_FUNCTION__ << ": Query target for an active DNS query changed!");

	if (!m_dns_lookup->bLookupDone) {
		DEBUG("waiting for dns on [" << sHostname << "] to finish...");
		return EAGAIN;
	}

	if (m_dns_lookup->ares_status != ARES_SUCCESS) {
		DEBUG("Error while looking up [" << sHostname << "]: "
				<< ares_strerror(m_dns_lookup->ares_status));
		delete m_dns_lookup;
		m_dns_lookup = NULL;
		return ETIMEDOUT;
	}

#ifdef HAVE_IPV6
	memcpy(csSockAddr.GetAddr6(), m_dns_lookup->addr.GetAddr6(), sizeof(in6_addr));
#endif
	memcpy(csSockAddr.GetAddr(), m_dns_lookup->addr.GetAddr(), sizeof(in_addr));
	csSockAddr.SetIPv6(m_dns_lookup->addr.GetIPv6());
	SetIPv6(csSockAddr.GetIPv6());

	DEBUG("GetAddrInfo() done for " << sHostname.c_str());

	delete m_dns_lookup;
	m_dns_lookup = NULL;

	return 0;
}
#endif

unsigned int CSockManager::GetAnonConnectionCount(const CString &sIP) const {
	const_iterator it;
	unsigned int ret = 0;

	for (it = begin(); it != end(); it++) {
		Csock *pSock = *it;
		// Logged in CClients have "USR::<username>" as their sockname
		if (pSock->GetRemoteIP() == sIP && pSock->GetSockName().Left(5) != "USR::") {
			ret++;
		}
	}

	DEBUG("There are [" << ret << "] clients from [" << sIP << "]");

	return ret;
}

#ifdef HAVE_ARES
static void SocketReadyCallback(EV_P_ ev_io *sock, int revents)
{
	ares_socket_t read_fd = ARES_SOCKET_BAD;
	ares_socket_t write_fd = ARES_SOCKET_BAD;
	ares_socket_t fd = (ares_socket_t) sock->fd;

	if (revents & EV_READ)
		read_fd = fd;
	if (revents & EV_WRITE)
		write_fd = fd;

	ares_process_fd(GetAres(), read_fd, write_fd);
}

static void AresSocketCallback(void *data, ares_socket_t fd, int readable, int writeable)
{
#warning this is ugly and causes leaks, ideas?
	static map<ares_socket_t, ev_io *> watchers;
	map<ares_socket_t, ev_io *>::iterator it = watchers.find(fd);

	if (!readable && !writeable)
	{
		// Remove that watcher
		if (it != watchers.end())
		{
			ev_io_stop(EV_DEFAULT_UC_ it->second);
			delete it->second;
			watchers.erase(it);
		}
		return;
	}

	// c-ares either adds a new fd or changes an existing fd's settings
	ev_io *io;
	if (it != watchers.end())
		io = it->second;
	else {
		io = new ev_io;
		watchers[fd] = io;
		ev_io_init(io, SocketReadyCallback, fd, 0);
	}

	int flags = 0;
	if (readable)
		flags |= EV_READ;
	if (writeable)
		flags |= EV_WRITE;

	ev_io_stop(EV_DEFAULT_UC_ io);
	ev_io_set(io, fd, flags);
	ev_io_start(EV_DEFAULT_UC_ io);
}
#endif
