/** @file
*
*    Copyright (c) 1999-2009 Jim Hull <imaginos@imaginos.net>
*    All rights reserved
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list
* of conditions and the following disclaimer in the documentation and/or other materials
*  provided with the distribution.
* Redistributions in any form must be accompanied by information on how to obtain
* complete source code for this software and any accompanying software that uses this software.
* The source code must either be included in the distribution or be available for no more than
* the cost of distribution plus a nominal fee, and must be freely redistributable
* under reasonable conditions. For an executable file, complete source code means the source
* code for all modules it contains. It does not include source code for modules or files
* that typically accompany the major components of the operating system on which the executable file runs.
*
* THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
* BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
* OR NON-INFRINGEMENT, ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OF THIS SOFTWARE BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
* PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
* TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*
* $Revision: 1.105 $
*/

#include "Csocket.h"
#ifdef __NetBSD__
#include <sys/param.h>
#endif /* __NetBSD__ */

#include <sstream>
#include <list>

#define CS_SRANDBUFFER 128

using namespace std;

#ifndef _NO_CSOCKET_NS // some people may not want to use a namespace
namespace Csocket
{
#endif /* _NO_CSOCKET_NS */

static int g_iCsockSSLIdx = 0; //!< this get setup once in InitSSL
int GetCsockClassIdx()
{
	return( g_iCsockSSLIdx );
}

#ifdef _WIN32
static const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
	if( af == AF_INET )
	{
		struct sockaddr_in in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		memcpy( &in.sin_addr, src, sizeof(struct in_addr) );
		getnameinfo( (struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST );
		return dst;
	}
	else if( af == AF_INET6 )
	{
		struct sockaddr_in6 in;
		memset( &in, 0, sizeof(in) );
		in.sin6_family = AF_INET6;
		memcpy( &in.sin6_addr, src, sizeof(struct in_addr6) );
		getnameinfo( (struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST );
		return dst;
	}
	return( NULL );
}

static inline void set_non_blocking(int fd)
{
	u_long iOpts = 1;
	ioctlsocket( fd, FIONBIO, &iOpts );
}

static inline void set_close_on_exec(int fd)
{
	// TODO add this for windows
	// see http://gcc.gnu.org/ml/java-patches/2002-q1/msg00696.html
	// for infos on how to do this
}
#else
static inline void set_non_blocking(int fd)
{
	int fdflags = fcntl(fd, F_GETFL, 0);
	if ( fdflags < 0 )
		return; // Ignore errors
	fcntl( fd, F_SETFL, fdflags|O_NONBLOCK );
}

static inline void set_close_on_exec(int fd)
{
	int fdflags = fcntl(fd, F_GETFD, 0);
	if ( fdflags < 0 )
		return; // Ignore errors
	fcntl( fd, F_SETFD, fdflags|FD_CLOEXEC);
}
#endif /* _WIN32 */

#ifdef HAVE_LIBSSL
Csock *GetCsockFromCTX( X509_STORE_CTX *pCTX )
{
	Csock *pSock = NULL;
	SSL *pSSL = (SSL *)X509_STORE_CTX_get_ex_data( pCTX, SSL_get_ex_data_X509_STORE_CTX_idx() );
	if( pSSL )
		pSock = (Csock *)SSL_get_ex_data( pSSL, GetCsockClassIdx() );
	return( pSock );
}
#endif /* HAVE_LIBSSL */


#ifndef HAVE_IPV6

// this issue here is getaddrinfo has a significant behavior difference when dealing with round robin dns on an
// ipv4 network. This is not desirable IMHO. so when this is compiled without ipv6 support backwards compatibility
// is maintained.

static int __GetHostByName( const CS_STRING & sHostName, struct in_addr *paddr, u_int iNumRetries )
{
	int iReturn = HOST_NOT_FOUND;
	struct hostent *hent = NULL;
#ifdef __linux__
	char hbuff[2048];
	struct hostent hentbuff;

	int err;
	for( u_int a = 0; a < iNumRetries; a++ )
	{
		memset( (char *)hbuff, '\0', 2048 );
		iReturn = gethostbyname_r( sHostName.c_str(), &hentbuff, hbuff, 2048, &hent, &err );

		if ( iReturn == 0 )
			break;

		if ( iReturn != TRY_AGAIN )
		{
			CS_DEBUG( "gethostyname_r: " << hstrerror( h_errno ) );
			break;
		}

	}
	if ( ( !hent ) && ( iReturn == 0 ) )
		iReturn = HOST_NOT_FOUND;
#else
	for( u_int a = 0; a < iNumRetries; a++ )
	{
		iReturn = HOST_NOT_FOUND;
		hent = gethostbyname( sHostName.c_str() );

		if ( hent )
		{
			iReturn = 0;
			break;
		}

		if( h_errno != TRY_AGAIN )
		{
#ifndef _WIN32
			CS_DEBUG( "gethostyname: " << hstrerror( h_errno ) );
#endif /* _WIN32 */
			break;
		}
	}

#endif /* __linux__ */

	if ( iReturn == 0 )
		memcpy( &paddr->s_addr, hent->h_addr_list[0], sizeof( paddr->s_addr ) );

	return( iReturn == TRY_AGAIN ? EAGAIN : iReturn );
}
#endif /* !HAVE_IPV6 */

int GetAddrInfo( const CS_STRING & sHostname, Csock *pSock, CSSockAddr & csSockAddr )
{
#ifndef HAVE_IPV6
	// if ipv6 is not enabled, then simply use gethostbyname, nothing special outside of this is done
	if( pSock )
		pSock->SetIPv6( false );
	csSockAddr.SetIPv6( false );
	if( __GetHostByName( sHostname, csSockAddr.GetAddr(), 3 ) == 0 )
		return( 0 );

#else /* HAVE_IPV6 */
	struct addrinfo *res = NULL;
	struct addrinfo hints;
	memset( (struct addrinfo *)&hints, '\0', sizeof( hints ) );
	hints.ai_family = csSockAddr.GetAFRequire();

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
#ifdef AI_ADDRCONFIG
	// this is suppose to eliminate host from appearing that this system can not support
	hints.ai_flags = AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

	if( pSock && ( pSock->GetType() == Csock::LISTENER || pSock->GetConState() == Csock::CST_BINDVHOST ) )
	{ // when doing a dns for bind only, set the AI_PASSIVE flag as suggested by the man page
		hints.ai_flags |= AI_PASSIVE;
	}

	int iRet = getaddrinfo( sHostname.c_str(), NULL, &hints, &res );
	if( iRet == EAI_AGAIN )
		return( EAGAIN ); // need to return telling the user to try again
	else if( ( iRet == 0 ) && ( res ) )
	{ 
		std::list<struct addrinfo *> lpTryAddrs;
		bool bFound = false;
		for( struct addrinfo *pRes = res; pRes; pRes = pRes->ai_next )
		{ // pass through the list building out a lean list of candidates to try. AI_CONFIGADDR doesn't always seem to work
#ifdef __sun
			if( ( pRes->ai_socktype != SOCK_STREAM ) || ( pRes->ai_protocol != IPPROTO_TCP && pRes->ai_protocol != IPPROTO_IP ) )
#else
			if( ( pRes->ai_socktype != SOCK_STREAM ) || ( pRes->ai_protocol != IPPROTO_TCP ) )
#endif /* __sun work around broken impl of getaddrinfo */
				continue;
			
			if( ( csSockAddr.GetAFRequire() != CSSockAddr::RAF_ANY ) && ( pRes->ai_family != csSockAddr.GetAFRequire() ) )
				continue; // they requested a special type, so be certain we woop past anything unwanted
			lpTryAddrs.push_back( pRes );
		}
		for( std::list<struct addrinfo *>::iterator it = lpTryAddrs.begin(); it != lpTryAddrs.end();  )
		{ // cycle through these, leaving the last iterator for the outside caller to call, so if there is an error it can call the events
			struct addrinfo * pRes = *it;
			bool bTryConnect = false;
			if( pRes->ai_family == AF_INET )
			{
				if( pSock )
					pSock->SetIPv6( false );
				csSockAddr.SetIPv6( false );
				struct sockaddr_in *pTmp = (struct sockaddr_in *)pRes->ai_addr;
				memcpy( csSockAddr.GetAddr(), &(pTmp->sin_addr), sizeof( *(csSockAddr.GetAddr()) ) );
				if( pSock && pSock->GetConState() == Csock::CST_DESTDNS && pSock->GetType() == Csock::OUTBOUND )
				{
					bTryConnect = true;
				}
				else
				{
					bFound = true;
					break;
				}
			}
			else if( pRes->ai_family == AF_INET6 )
			{
				if( pSock )
					pSock->SetIPv6( true );
				csSockAddr.SetIPv6( true );
				struct sockaddr_in6 *pTmp = (struct sockaddr_in6 *)pRes->ai_addr;
				memcpy( csSockAddr.GetAddr6(), &(pTmp->sin6_addr), sizeof( *(csSockAddr.GetAddr6()) ) );
				if( pSock && pSock->GetConState() == Csock::CST_DESTDNS && pSock->GetType() == Csock::OUTBOUND )
				{
					bTryConnect = true;
				}
				else
				{
					bFound = true;
					break;
				}
			}

			it++; // increment the iterator her so we know if its the last element or not

			if( bTryConnect && it != lpTryAddrs.end() )
			{ // save the last attempt for the outer loop, the issue then becomes that the error is thrown on the last failure
				if( pSock->CreateSocksFD() && pSock->Connect( pSock->GetBindHost(), true ) )
				{
					pSock->SetSkipConnect( true ); // this tells the socket that the connection state has been started
					bFound = true;
					break;
				}
			}
			else if( bTryConnect )
			{
				bFound = true;
			}
		}

		freeaddrinfo( res );
		if( bFound ) // the data pointed to here is invalid now, but the pointer itself is a good test
		{
			return( 0 );
		}
	}
#endif /* ! HAVE_IPV6 */
	return( ETIMEDOUT );
}

bool InitCsocket()
{
#ifdef _WIN32
	WSADATA wsaData;
	int iResult = WSAStartup( MAKEWORD( 2, 2 ), &wsaData );
	if( iResult != NO_ERROR )
		return( false );
#endif /* _WIN32 */
#ifdef HAVE_LIBSSL
	if( !InitSSL() )
		return( false );
#endif /* HAVE_LIBSSL */

	ev_default_loop(0);

	return( true );
}

void ShutdownCsocket()
{
	ev_default_destroy();

#ifdef HAVE_LIBSSL
	ERR_free_strings();
#endif /* HAVE_LIBSSL */
#ifdef _WIN32
	WSACleanup();
#endif /* _WIN32 */
}

#ifdef HAVE_LIBSSL
bool InitSSL( ECompType eCompressionType )
{
	SSL_load_error_strings();
	if ( SSL_library_init() != 1 )
	{
		CS_DEBUG( "SSL_library_init() failed!" );
		return( false );
	}

#ifndef _WIN32
	if ( access( "/dev/urandom", R_OK ) == 0 )
		RAND_load_file( "/dev/urandom", 1024 );
	else if( access( "/dev/random", R_OK ) == 0 )
		RAND_load_file( "/dev/random", 1024 );
	else
	{
		CS_DEBUG( "Unable to locate entropy location! Tried /dev/urandom and /dev/random" );
		return( false );
	}
#endif /* _WIN32 */

	COMP_METHOD *cm = NULL;

	if ( CT_ZLIB & eCompressionType )
	{
		cm = COMP_zlib();
		if ( cm )
			SSL_COMP_add_compression_method( CT_ZLIB, cm );
	}

	if ( CT_RLE & eCompressionType )
	{
		cm = COMP_rle();
		if ( cm )
			SSL_COMP_add_compression_method( CT_RLE, cm );
	}

	// setting this up once in the begining
	g_iCsockSSLIdx = SSL_get_ex_new_index( 0, (void *)"CsockGlobalIndex", NULL, NULL, NULL);

	return( true );
}

void SSLErrors( const char *filename, u_int iLineNum )
{
	unsigned long iSSLError = 0;
	while( ( iSSLError = ERR_get_error() ) != 0 )
	{
		CS_DEBUG( "at " << filename << ":" << iLineNum );
		char szError[512];
		memset( (char *) szError, '\0', 512 );
		ERR_error_string_n( iSSLError, szError, 511 );
		if ( strlen( szError ) > 0 )
			CS_DEBUG( szError );
	}
}
#endif /* HAVE_LIBSSL */

void __Perror( const CS_STRING & s, const char *pszFile, unsigned int iLineNo )
{
#if defined(__sun) || defined(_WIN32) || (defined(__NetBSD_Version__) && __NetBSD_Version__ < 4000000000)
	std::cerr << s << "(" << pszFile << ":" << iLineNo << "): " << strerror( GetSockError() ) << endl;
#else
	char buff[512];
	memset( (char *)buff, '\0', 512 );
	if ( strerror_r( GetSockError(), buff, 511 ) == 0 )
		std::cerr << s << "(" << pszFile << ":" << iLineNo << "): " << buff << endl;
	else
		std::cerr << s << "(" << pszFile << ":" << iLineNo << "): Unknown Error Occured " << endl;
#endif /* __sun */
}

#ifndef _NO_CSOCKET_NS // some people may not want to use a namespace
}
using namespace Csocket;
#endif /* _NO_CSOCKET_NS */

CCron::CCron()
{
	m_iCycles = 0;
	m_iMaxCycles = 0;

	m_timer.data = this;
	ev_timer_init(&m_timer, &TimerCallback, 0, 0);
}

CCron::~CCron()
{
	Stop();
}

void CCron::StartMaxCycles( int TimeSequence, u_int iMaxCycles )
{
	Stop();
	ev_timer_set(&m_timer, TimeSequence, TimeSequence);
	ev_timer_start(EV_DEFAULT_UC_ &m_timer);
	m_iMaxCycles = iMaxCycles;
}

void CCron::Start( int TimeSequence, bool bFirstCall )
{
	int after = TimeSequence;
	if (bFirstCall)
		after = 0;
	Stop();
	ev_timer_set(&m_timer, after, TimeSequence);
	ev_timer_start(EV_DEFAULT_UC_ &m_timer);
	m_iMaxCycles = 0;
}

void CCron::Stop()
{
	ev_timer_stop(EV_DEFAULT_UC_ &m_timer);
}

void CCron::TimerCallback(EV_P_ ev_timer *timer, int revents) {
	CCron *p = (CCron *) timer->data;
	p->RunJob();

	if (p->m_iMaxCycles > 0 && ++p->m_iCycles >= p->m_iMaxCycles)
		p->Stop();
}

int CCron::GetInterval() const { return( m_timer.repeat ); }
u_int CCron::GetMaxCycles() const { return( m_iMaxCycles ); }
u_int CCron::GetCyclesLeft() const { return( ( m_iMaxCycles > m_iCycles ? ( m_iMaxCycles - m_iCycles ) : 0 ) ); }

bool CCron::isValid() { return( ev_is_active(&m_timer) ); }
const CS_STRING & CCron::GetName() const { return( m_sName ); }
void CCron::SetName( const CS_STRING & sName ) { m_sName = sName; }

Csock::Csock( int itimeout )
{
#ifdef HAVE_LIBSSL
	m_pCerVerifyCB = NULL;
#endif /* HAVE_LIBSSL */
	Init( "", 0, itimeout );
}

Csock::Csock( const CS_STRING & sHostname, u_short iport, int itimeout )
{
#ifdef HAVE_LIBSSL
	m_pCerVerifyCB = NULL;
#endif /* HAVE_LIBSSL */
	Init( sHostname, iport, itimeout );
}

// override this for accept sockets
Csock *Csock::GetSockObj( const CS_STRING & sHostname, u_short iPort )
{
	return( NULL );
}

#ifdef _WIN32
#define CS_CLOSE closesocket
#else
#define CS_CLOSE close
#endif /* _WIN32 */

Csock::~Csock()
{
#ifdef HAVE_LIBSSL
	FREE_SSL();
	FREE_CTX();
#endif /* HAVE_LIBSSL */

	if ( GetRSock() != GetWSock() )
	{
		if( GetRSock() >= 0 )
			CS_CLOSE( GetRSock() );
		if( GetWSock() >= 0 )
			CS_CLOSE( GetWSock() );
	} else if( GetRSock() >= 0 )
		CS_CLOSE( GetRSock() );

	SetSock(-1);

	// delete any left over crons
	while (!m_sCrons.empty()) {
		delete *m_sCrons.begin();
		m_sCrons.erase(m_sCrons.begin());
	}

	ev_io_stop(EV_DEFAULT_UC_ &m_read_io);
	ev_io_stop(EV_DEFAULT_UC_ &m_write_io);
	ev_timer_stop(EV_DEFAULT_UC_ &m_io_timeout);
}

void Csock::Dereference()
{
	SetSock(-1);

#ifdef HAVE_LIBSSL
	m_ssl = NULL;
	m_ssl_ctx = NULL;
#endif /* HAVE_LIBSSL */

	m_sCrons.clear();
	Close( CLT_DEREFERENCE );
}

void Csock::Copy( const Csock & cCopy )
{
	SetRSock(cCopy.GetRSock());
	SetWSock(cCopy.GetWSock());

	m_iport			= cCopy.m_iport;
	m_iRemotePort	= cCopy.m_iRemotePort;
	m_iLocalPort	= cCopy.m_iLocalPort;
	m_iConnType		= cCopy.m_iConnType;
	m_iMethod		= cCopy.m_iMethod;
	m_bssl			= cCopy.m_bssl;
	m_bIsConnected	= cCopy.m_bIsConnected;
	m_bFullsslAccept	= cCopy.m_bFullsslAccept;
	m_bsslEstablished	= cCopy.m_bsslEstablished;
	m_bEnableReadLine	= cCopy.m_bEnableReadLine;
	m_bPauseRead		= cCopy.m_bPauseRead;
	m_shostname		= cCopy.m_shostname;
	m_sbuffer		= cCopy.m_sbuffer;
	m_sSockName		= cCopy.m_sSockName;
	m_sPemFile		= cCopy.m_sPemFile;
	m_sCipherType	= cCopy.m_sCipherType;
	m_sParentName	= cCopy.m_sParentName;
	m_sSend			= cCopy.m_sSend;
	m_sPemPass		= cCopy.m_sPemPass;
	m_sLocalIP		= cCopy.m_sLocalIP;
	m_sRemoteIP		= cCopy.m_sRemoteIP;
	m_eCloseType	= cCopy.m_eCloseType;

	m_iBytesRead		= cCopy.m_iBytesRead;
	m_iBytesWritten		= cCopy.m_iBytesWritten;
	m_tStartTime		= cCopy.m_tStartTime;
	m_iMaxStoredBufferLength	= cCopy.m_iMaxStoredBufferLength;

	SetTimeout(cCopy.GetTimeout(), cCopy.GetTimeoutType());

	m_address			= cCopy.m_address;
	m_bindhost			= cCopy.m_bindhost;
	m_bIsIPv6			= cCopy.m_bIsIPv6;
	m_bSkipConnect		= cCopy.m_bSkipConnect;

#ifdef HAVE_LIBSSL
	m_iRequireClientCertFlags = cCopy.m_iRequireClientCertFlags;
	m_sSSLBuffer	= cCopy.m_sSSLBuffer;

	FREE_SSL();
	FREE_CTX(); // be sure to remove anything that was already here
	m_ssl				= cCopy.m_ssl;
	m_ssl_ctx			= cCopy.m_ssl_ctx;

	m_pCerVerifyCB		= cCopy.m_pCerVerifyCB;

#endif /* HAVE_LIBSSL */

	while (!m_sCrons.empty()) {
		delete *m_sCrons.begin();
		m_sCrons.erase(m_sCrons.begin());
	}

	m_sCrons			= cCopy.m_sCrons;

	m_sBindHost			= cCopy.m_sBindHost;
	m_iCurBindCount		= cCopy.m_iCurBindCount;

	SetConState(cCopy.GetConState());
}

Csock & Csock::operator<<( const CS_STRING & s )
{
	Write( s );
	return( *this );
}

Csock & Csock::operator<<( ostream & ( *io )( ostream & ) )
{
	Write( "\r\n" );
	return( *this );
}

Csock & Csock::operator<<( int i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( unsigned int i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( long i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( unsigned long i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( unsigned long long i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( float i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}
Csock & Csock::operator<<( double i )
{
	stringstream s;
	s << i;
	Write( s.str() );
	return( *this );
}

bool Csock::Connect( const CS_STRING & sBindHost, bool bSkipSetup )
{
	if( m_bSkipConnect )
	{ // this was already called, so skipping now. this is to allow easy pass through
		if ( GetConState() != CST_OK )
		{
			SetConState(GetSSL() ? CST_CONNECTSSL : CST_OK);
		}
		return( true );
	}
	// bind to a hostname if requested
	m_sBindHost = sBindHost;
	if ( !bSkipSetup )
	{
		if ( !sBindHost.empty() )
		{
			// try to bind 3 times, otherwise exit failure
			bool bBound = false;
			for( int a = 0; a < 3 && !bBound; a++ )
			{
				if ( SetupVHost() )
					bBound = true;
#ifdef _WIN32
				Sleep( 5000 );
#else
				usleep( 5000 );	// quick pause, common lets BIND!)(!*!
#endif /* _WIN32 */
			}

			if ( !bBound )
			{
				CS_DEBUG( "Failure to bind to " << sBindHost );
				return( false );
			}
		}

		int iDNSRet = ETIMEDOUT;
		while( true )
		{
			iDNSRet = DNSLookup( DNS_VHOST );
			if ( iDNSRet == EAGAIN )
				continue;

			break;
		}
		if ( iDNSRet != 0 )
			return( false );

	}

	// set it none blocking
	set_non_blocking( GetRSock() );

	m_iConnType = OUTBOUND;

	int ret = -1;
	if( !GetIPv6() )
		ret = connect( GetRSock(), (struct sockaddr *)m_address.GetSockAddr(), m_address.GetSockAddrLen() );
#ifdef HAVE_IPV6
	else
		ret = connect( GetRSock(), (struct sockaddr *)m_address.GetSockAddr6(), m_address.GetSockAddrLen6() );
#endif /* HAVE_IPV6 */
#ifndef _WIN32
	if ( ( ret == -1 ) && ( GetSockError() != EINPROGRESS ) )
#else
	if ( ( ret == -1 ) && ( GetSockError() != EINPROGRESS ) && ( GetSockError() != WSAEWOULDBLOCK ) )
#endif /* _WIN32 */

	{
		CS_DEBUG( "Connect Failed. ERRNO [" << GetSockError() << "] FD [" << GetRSock() << "]" );
		return( false );
	}

	if ( GetConState() != CST_OK )
	{
		SetConState(GetSSL() ? CST_CONNECTSSL : CST_OK);
	}

	return( true );
}

bool Csock::Listen( u_short iPort, int iMaxConns, const CS_STRING & sBindHost, u_int iTimeout )
{
	m_iConnType = LISTENER;
	SetTimeout(iTimeout, GetTimeoutType());

	m_sBindHost = sBindHost;
	if ( !sBindHost.empty() )
	{
		if( GetAddrInfo( sBindHost, m_address ) != 0 )
			return( false );
	}

	SetRSock(SOCKET(true));

	if ( GetRSock() == -1 )
		return( false );
	SetWSock(GetRSock());

	m_address.SinFamily();
	m_address.SinPort( iPort );

	if( !GetIPv6() )
	{
		if ( bind( GetRSock(), (struct sockaddr *) m_address.GetSockAddr(), m_address.GetSockAddrLen() ) == -1 )
			return( false );
	}
#ifdef HAVE_IPV6
	else
	{
		if ( bind( GetRSock(), (struct sockaddr *) m_address.GetSockAddr6(), m_address.GetSockAddrLen6() ) == -1 )
			return( false );
	}
#endif /* HAVE_IPV6 */

	if ( listen( GetRSock(), iMaxConns ) == -1 )
		return( false );

	// set it none blocking
	set_non_blocking( GetRSock() );

	return( true );
}

int Csock::Accept( CS_STRING & sHost, u_short & iRPort )
{
	int iSock = -1;
	if( !GetIPv6() )
	{
		struct sockaddr_in client;
		socklen_t clen = sizeof( client );
		iSock = accept( GetRSock(), (struct sockaddr *) &client, &clen );
		if( iSock != -1 )
		{
			getpeername( iSock, (struct sockaddr *) &client, &clen );
			sHost = inet_ntoa( client.sin_addr );
			iRPort = ntohs( client.sin_port );
		}
	}
#ifdef HAVE_IPV6
	else
	{
		char straddr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 client;
		socklen_t clen = sizeof( client );
		iSock = accept( GetRSock(), (struct sockaddr *) &client, &clen );
		if( iSock != -1 )
		{
			getpeername( iSock, (struct sockaddr *) &client, &clen );
			if( inet_ntop( AF_INET6, &client.sin6_addr, straddr, sizeof(straddr) ) > 0 )
			{
				sHost = straddr;
				iRPort = ntohs( client.sin6_port );
			}
		}
	}
#endif /* HAVE_IPV6 */

	if ( iSock != -1 )
	{
		// Make it close-on-exec
		set_close_on_exec( iSock );

		// make it none blocking
		set_non_blocking( iSock );

		if ( !ConnectionFrom( sHost, iRPort ) )
		{
			CS_CLOSE( iSock );
			iSock = -1;
		}

	}

	return( iSock );
}

bool Csock::AcceptSSL()
{
#ifdef HAVE_LIBSSL
	if ( !m_ssl )
		if ( !SSLServerSetup() )
			return( false );

	int err = SSL_accept( m_ssl );

	if ( err == 1 )
	{
		m_bFullsslAccept = true;
		return( true );
	}

	m_bFullsslAccept = false;

	int sslErr = SSL_get_error( m_ssl, err );

	if ( ( sslErr == SSL_ERROR_WANT_READ ) || ( sslErr == SSL_ERROR_WANT_WRITE ) )
		return( true );

	SSLErrors( __FILE__, __LINE__ );

#endif /* HAVE_LIBSSL */

	return( false );
}

bool Csock::SSLClientSetup()
{
#ifdef HAVE_LIBSSL
	m_bssl = true;
	FREE_SSL();
	FREE_CTX();

	switch( m_iMethod )
	{
		case SSL2:
			m_ssl_ctx = SSL_CTX_new ( SSLv2_client_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv2_client_method failed!" );
				return( false );
			}
			break;

		case SSL3:
			m_ssl_ctx = SSL_CTX_new ( SSLv3_client_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv3_client_method failed!" );
				return( false );
			}
			break;
		case TLS1:
			m_ssl_ctx = SSL_CTX_new ( TLSv1_client_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... TLSv1_client_method failed!" );
				return( false );
			}
			break;
		case SSL23:
		default:
			m_ssl_ctx = SSL_CTX_new ( SSLv23_client_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv23_client_method failed!" );
				return( false );
			}
			break;
	}


	SSL_CTX_set_default_verify_paths( m_ssl_ctx );

	if ( !m_sPemFile.empty() )
	{	// are we sending a client cerificate ?
		SSL_CTX_set_default_passwd_cb( m_ssl_ctx, PemPassCB );
		SSL_CTX_set_default_passwd_cb_userdata( m_ssl_ctx, (void *)this );

		//
		// set up the CTX
		if ( SSL_CTX_use_certificate_file( m_ssl_ctx, m_sPemFile.c_str() , SSL_FILETYPE_PEM ) <= 0 )
		{
			CS_DEBUG( "Error with PEM file [" << m_sPemFile << "]" );
			SSLErrors( __FILE__, __LINE__ );
		}

		if ( SSL_CTX_use_PrivateKey_file( m_ssl_ctx, m_sPemFile.c_str(), SSL_FILETYPE_PEM ) <= 0 )
		{
			CS_DEBUG( "Error with PEM file [" << m_sPemFile << "]" );
			SSLErrors( __FILE__, __LINE__ );
		}
	}

	m_ssl = SSL_new ( m_ssl_ctx );
	if ( !m_ssl )
		return( false );

	SSL_set_rfd( m_ssl, GetRSock() );
	SSL_set_wfd( m_ssl, GetWSock() );
	SSL_set_verify( m_ssl, SSL_VERIFY_PEER, ( m_pCerVerifyCB ? m_pCerVerifyCB : CertVerifyCB ) );
	SSL_set_ex_data( m_ssl, GetCsockClassIdx(), this );

	SSLFinishSetup( m_ssl );
	return( true );
#else
	return( false );

#endif /* HAVE_LIBSSL */
}

bool Csock::SSLServerSetup()
{
#ifdef HAVE_LIBSSL
	m_bssl = true;
	FREE_SSL();
	FREE_CTX();

	switch( m_iMethod )
	{
		case SSL2:
			m_ssl_ctx = SSL_CTX_new ( SSLv2_server_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv2_server_method failed!" );
				return( false );
			}
			break;

		case SSL3:
			m_ssl_ctx = SSL_CTX_new ( SSLv3_server_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv3_server_method failed!" );
				return( false );
			}
			break;

		case TLS1:
			m_ssl_ctx = SSL_CTX_new ( TLSv1_server_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... TLSv1_server_method failed!" );
				return( false );
			}
			break;

		case SSL23:
		default:
			m_ssl_ctx = SSL_CTX_new ( SSLv23_server_method() );
			if ( !m_ssl_ctx )
			{
				CS_DEBUG( "WARNING: MakeConnection .... SSLv23_server_method failed!" );
				return( false );
			}
			break;
	}

	SSL_CTX_set_default_verify_paths( m_ssl_ctx );

	// set the pemfile password
	SSL_CTX_set_default_passwd_cb( m_ssl_ctx, PemPassCB );
	SSL_CTX_set_default_passwd_cb_userdata( m_ssl_ctx, (void *)this );

	if ( ( m_sPemFile.empty() ) || ( access( m_sPemFile.c_str(), R_OK ) != 0 ) )
	{
		CS_DEBUG( "There is a problem with [" << m_sPemFile << "]" );
		return( false );
	}

	//
	// set up the CTX
	if ( SSL_CTX_use_certificate_chain_file( m_ssl_ctx, m_sPemFile.c_str() ) <= 0 )
	{
		CS_DEBUG( "Error with PEM file [" << m_sPemFile << "]" );
		SSLErrors( __FILE__, __LINE__ );
		return( false );
	}

	if ( SSL_CTX_use_PrivateKey_file( m_ssl_ctx, m_sPemFile.c_str(), SSL_FILETYPE_PEM ) <= 0 )
	{
		CS_DEBUG( "Error with PEM file [" << m_sPemFile << "]" );
		SSLErrors( __FILE__, __LINE__ );
		return( false );
	}

	if ( SSL_CTX_set_cipher_list( m_ssl_ctx, m_sCipherType.c_str() ) <= 0 )
	{
		CS_DEBUG( "Could not assign cipher [" << m_sCipherType << "]" );
		return( false );
	}

	//
	// setup the SSL
	m_ssl = SSL_new ( m_ssl_ctx );
	if ( !m_ssl )
		return( false );

	// Call for client Verification
	SSL_set_rfd( m_ssl, GetRSock() );
	SSL_set_wfd( m_ssl, GetWSock() );
	SSL_set_accept_state( m_ssl );
	if ( m_iRequireClientCertFlags )
	{
		SSL_set_verify( m_ssl, m_iRequireClientCertFlags, ( m_pCerVerifyCB ? m_pCerVerifyCB : CertVerifyCB ) );
		SSL_set_ex_data( m_ssl, GetCsockClassIdx(), this );
	}

	SSLFinishSetup( m_ssl );
	return( true );
#else
	return( false );
#endif /* HAVE_LIBSSL */
}

bool Csock::ConnectSSL( const CS_STRING & sBindhost )
{
#ifdef HAVE_LIBSSL
	if ( GetRSock() == -1 )
		if ( !Connect( sBindhost ) )
			return( false );
	if ( !m_ssl )
		if ( !SSLClientSetup() )
			return( false );

	bool bPass = true;

	set_non_blocking( GetRSock() );

	int iErr = SSL_connect( m_ssl );
	if ( iErr != 1 )
	{
		int sslErr = SSL_get_error( m_ssl, iErr );
		bPass = false;
		if( sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE )
			bPass = true;
#ifdef _WIN32
		else if( sslErr == SSL_ERROR_SYSCALL && iErr < 0 && GetLastError() == WSAENOTCONN )
		{ 
			// this seems to be an issue with win32 only. I've seen it happen on slow connections
			// the issue is calling this before select(), which isn't a problem on unix. Allowing this
			// to pass in this case is fine because subsequent ssl transactions will occur and the handshake
			// will finish. At this point, its just instantiating the handshake.
			bPass = true;
		}
#endif /* _WIN32 */
	} else
		bPass = true;

	if ( GetConState() != CST_OK )
		SetConState(CST_OK);
	return( bPass );
#else
	return( false );
#endif /* HAVE_LIBSSL */
}

bool Csock::Write( const char *data, int len )
{
	m_sSend.append( data, len );

	if (GetConState() != CST_OK)
		return( true );

	if (m_sSend.empty()) {
		// while we are not connected yet, we use m_write_io to find out
		// when we are connected, so we may not stop it in this case.
		if (IsConnected())
			ev_io_stop(EV_DEFAULT_UC_ &m_write_io);
		return( true );
	}

#ifdef HAVE_LIBSSL
	if ( m_bssl )
	{

		if ( m_sSSLBuffer.empty() ) // on retrying to write data, ssl wants the data in the SAME spot and the SAME size
			m_sSSLBuffer.append( m_sSend.data(), m_sSend.length());

		int iErr = SSL_write( m_ssl, m_sSSLBuffer.data(), m_sSSLBuffer.length() );

		if ( ( iErr < 0 ) && ( GetSockError() == ECONNREFUSED ) )
		{
			// If ret == -1, the underlying BIO reported an I/O error (man SSL_get_error)
			ConnectionRefused();
			return( false );
		}

		switch( SSL_get_error( m_ssl, iErr ) )
		{
			case SSL_ERROR_NONE:
			m_bsslEstablished = true;
			// all ok
			break;

			case SSL_ERROR_ZERO_RETURN:
			{
				// weird closer alert
				return( false );
			}

			case SSL_ERROR_WANT_READ:
			// retry
			break;

			case SSL_ERROR_WANT_WRITE:
			// retry
			break;

			case SSL_ERROR_SSL:
			{
				SSLErrors( __FILE__, __LINE__ );
				return( false );
			}
		}

		if ( iErr > 0 )
		{
			m_sSSLBuffer.clear();
			m_sSend.erase( 0, iErr );
			// reset the timer on successful write (we have to set it here because the write
			// bit might not always be set, so need to trigger)
			if ( TMO_WRITE & GetTimeoutType() )
				ResetTimer();

			m_iBytesWritten += (unsigned long long)iErr;
		}

		return( true );
	}
	else
#endif /* HAVE_LIBSSL */
	{
#ifdef _WIN32
		int bytes = send(GetWSock(), m_sSend.data(), m_sSend.length(), 0);
#else
		int bytes = write(GetWSock(), m_sSend.data(), m_sSend.length());
#endif /* _WIN32 */

		if ( ( bytes == -1 ) && ( GetSockError() == ECONNREFUSED ) )
		{
			ConnectionRefused();
			return( false );
		}

#ifdef _WIN32
		if ( ( bytes <= 0 ) && ( GetSockError() != WSAEWOULDBLOCK ) )
			return( false );
#else
		if ( ( bytes <= 0 ) && ( GetSockError() != EAGAIN ) )
			return( false );
#endif /* _WIN32 */

		// delete the bytes we sent
		if ( bytes > 0 )
		{
			m_sSend.erase( 0, bytes );
			if ( TMO_WRITE & GetTimeoutType() )
				ResetTimer();	// reset the timer on successful write
			m_iBytesWritten += (unsigned long long)bytes;
		}
	}

	if (m_sSend.empty())
		ev_io_stop(EV_DEFAULT_UC_ &m_write_io);
	else
		ev_io_start(EV_DEFAULT_UC_ &m_write_io);

	return( true );
}

bool Csock::Write( const CS_STRING & sData )
{
	return( Write( sData.c_str(), sData.length() ) );
}

int Csock::Read( char *data, int len )
{
	int bytes = 0;

	if ( ( IsReadPaused() ) && ( SslIsEstablished() ) )
		return( READ_EAGAIN ); // allow the handshake to complete first

#ifdef HAVE_LIBSSL
	if ( m_bssl )
		bytes = SSL_read( m_ssl, data, len );
	else
#endif /* HAVE_LIBSSL */
#ifdef _WIN32
		bytes = recv( GetRSock(), data, len, 0 );
#else
		bytes = read( GetRSock(), data, len );
#endif /* _WIN32 */
	if ( bytes == -1 )
	{
		if ( GetSockError() == ECONNREFUSED )
			return( READ_CONNREFUSED );

		if ( GetSockError() == ETIMEDOUT )
			return( READ_TIMEDOUT );

		if ( ( GetSockError() == EINTR ) || ( GetSockError() == EAGAIN ) )
			return( READ_EAGAIN );

#ifdef _WIN32
		if ( GetSockError() == WSAEWOULDBLOCK )
			return( READ_EAGAIN );
#endif /* _WIN32 */

#ifdef HAVE_LIBSSL
		if ( m_bssl )
		{
			int iErr = SSL_get_error( m_ssl, bytes );
			if ( ( iErr != SSL_ERROR_WANT_READ ) && ( iErr != SSL_ERROR_WANT_WRITE ) )
				return( READ_ERR );
			else
				return( READ_EAGAIN );
		}
#else
		return( READ_ERR );
#endif /* HAVE_LIBSSL */
	}

	if( bytes > 0 ) // becareful not to add negative bytes :P
		m_iBytesRead += (unsigned long long)bytes;

	return( bytes );
}

CS_STRING Csock::GetLocalIP()
{
	if ( !m_sLocalIP.empty() )
		return( m_sLocalIP );

	int iSock = GetSock();

	if ( iSock < 0 )
		return( "" );

	if( !GetIPv6() )
	{
		struct sockaddr_in mLocalAddr;
		socklen_t mLocalLen = sizeof( mLocalAddr );
		if ( getsockname( iSock, (struct sockaddr *) &mLocalAddr, &mLocalLen ) == 0 )
			m_sLocalIP = inet_ntoa( mLocalAddr.sin_addr );
	}
#ifdef HAVE_IPV6
	else
	{
		char straddr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 mLocalAddr;
		socklen_t mLocalLen = sizeof( mLocalAddr );
		if ( ( getsockname( iSock, (struct sockaddr *) &mLocalAddr, &mLocalLen ) == 0 )
			&& ( inet_ntop( AF_INET6, &mLocalAddr.sin6_addr, straddr, sizeof(straddr) ) ) )
		{
			m_sLocalIP = straddr;
		}
	}
#endif /* HAVE_IPV6 */

	return( m_sLocalIP );
}

CS_STRING Csock::GetRemoteIP()
{
	if ( !m_sRemoteIP.empty() )
		return( m_sRemoteIP );

	int iSock = GetSock();

	if ( iSock < 0 )
	{
		std::cerr << "What the hell is wrong with my fd!?" << endl;
		return( "" );
	}

	if( !GetIPv6() )
	{
		struct sockaddr_in mRemoteAddr;
		socklen_t mRemoteLen = sizeof( mRemoteAddr );
		if ( getpeername( iSock, (struct sockaddr *) &mRemoteAddr, &mRemoteLen ) == 0 )
			m_sRemoteIP = inet_ntoa( mRemoteAddr.sin_addr );
	}
#ifdef HAVE_IPV6
	else
	{
		char straddr[INET6_ADDRSTRLEN];
		struct sockaddr_in6 mRemoteAddr;
		socklen_t mRemoteLen = sizeof( mRemoteAddr );
		if ( ( getpeername( iSock, (struct sockaddr *) &mRemoteAddr, &mRemoteLen ) == 0 )
			&& ( inet_ntop( AF_INET6, &mRemoteAddr.sin6_addr, straddr, sizeof(straddr) ) ) )
		{
			m_sRemoteIP = straddr;
		}
	}
#endif /* HAVE_IPV6 */

	return( m_sRemoteIP );
}

bool Csock::IsConnected() { return( m_bIsConnected ); }
void Csock::SetIsConnected( bool b ) { m_bIsConnected = b; }

void Csock::SetRSock( int iSock )
{
	ev_io_stop(EV_DEFAULT_UC_ &m_read_io);
	ev_io_set(&m_read_io, iSock, EV_READ);
	if (iSock >= 0 && !IsReadPaused())
		ev_io_start(EV_DEFAULT_UC_ &m_read_io);
}
void Csock::SetWSock( int iSock )
{
	ev_io_stop(EV_DEFAULT_UC_ &m_write_io);
	ev_io_set(&m_write_io, iSock, EV_WRITE);
	if (iSock >= 0)
		ev_io_start(EV_DEFAULT_UC_ &m_write_io);
}
void Csock::SetSock( int iSock ) { SetWSock(iSock); SetRSock(iSock); }
int Csock::GetRSock() const { return( m_read_io.fd ); }
int Csock::GetWSock() const { return( m_write_io.fd ); }
int Csock::GetSock() const { return( GetRSock() ); }
void Csock::ResetTimer() { ev_timer_again(EV_DEFAULT_UC_ &m_io_timeout); }
bool Csock::IsReadPaused() { return( m_bPauseRead ); }

void Csock::PauseRead()
{
	m_bPauseRead = true;
	ev_io_stop(EV_DEFAULT_UC_ &m_read_io);
	if (m_Manager)
		m_Manager->AddAttentionSock(this);
}

void Csock::UnPauseRead()
{
	m_bPauseRead = false;
	ev_io_start(EV_DEFAULT_UC_ &m_read_io);
	ResetTimer();
	PushBuff( "", 0, true );
}

void Csock::SetTimeout( int iTimeout, u_int iTimeoutType )
{
	m_iTimeoutType = iTimeoutType;
	m_io_timeout.repeat = iTimeout;
	ResetTimer();
}

void Csock::SetTimeoutType( u_int iTimeoutType ) { m_iTimeoutType = iTimeoutType; }
int Csock::GetTimeout() const { return m_io_timeout.repeat; }
u_int Csock::GetTimeoutType() const { return( m_iTimeoutType ); }

void Csock::CheckTimeout(EV_P_ ev_timer *timeout, int revents)
{
	Csock *pSock = (Csock *) timeout->data;

	if (pSock->GetConState() != CST_OK) {
		// Not yet connected so won't time out
		pSock->ResetTimer();
		return;
	}

	if (pSock->IsReadPaused())
		// UnPauseRead() will ResetTimer()
		return;

	pSock->Timeout();
	pSock->Close(CLT_NOW);
}

void Csock::PushBuff( const char *data, int len, bool bStartAtZero )
{
	if ( !m_bEnableReadLine )
		return;	// If the ReadLine event is disabled, just ditch here

	u_int iStartPos = ( m_sbuffer.empty() || bStartAtZero ? 0 : m_sbuffer.length() - 1 );

	if ( data )
		m_sbuffer.append( data, len );

	while( !m_bPauseRead && GetCloseType() == CLT_DONT  )
	{
		CS_STRING::size_type iFind = m_sbuffer.find( "\n", iStartPos );

		if ( iFind != CS_STRING::npos )
		{
			CS_STRING sBuff = m_sbuffer.substr( 0, iFind + 1 );	// read up to(including) the newline
			m_sbuffer.erase( 0, iFind + 1 );					// erase past the newline
			ReadLine( sBuff );
			iStartPos = 0; // reset this back to 0, since we need to look for the next newline here.

		} else
			break;
	}

	if ( ( m_iMaxStoredBufferLength > 0 ) && ( m_sbuffer.length() > m_iMaxStoredBufferLength ) )
		ReachedMaxBuffer(); // call the max read buffer event

}

CS_STRING & Csock::GetInternalReadBuffer() { return( m_sbuffer ); }
CS_STRING & Csock::GetInternalWriteBuffer() { return( m_sSend ); }
void Csock::SetMaxBufferThreshold( u_int iThreshold ) { m_iMaxStoredBufferLength = iThreshold; }
u_int Csock::GetMaxBufferThreshold() const { return( m_iMaxStoredBufferLength ); }
int Csock::GetType() const { return( m_iConnType ); }
void Csock::SetType( int iType ) { m_iConnType = iType; }
const CS_STRING & Csock::GetSockName() const { return( m_sSockName ); }
void Csock::SetSockName( const CS_STRING & sName ) { m_sSockName = sName; }
const CS_STRING & Csock::GetHostName() const { return( m_shostname ); }
void Csock::SetHostName( const CS_STRING & sHostname ) { m_shostname = sHostname; }
ev_tstamp Csock::GetStartTime() const { return( m_tStartTime ); }
unsigned long long Csock::GetBytesRead() const { return( m_iBytesRead ); }
void Csock::ResetBytesRead() { m_iBytesRead = 0; }
unsigned long long Csock::GetBytesWritten() const { return( m_iBytesWritten ); }
void Csock::ResetBytesWritten() { m_iBytesWritten = 0; }

double Csock::GetAvgRead( unsigned long long iSample )
{
	ev_tstamp iDifference = ev_now(EV_DEFAULT_UC) - m_tStartTime;

	// We need seconds, not milliseconds
	iSample /= 1000;

	if ( ( m_iBytesRead == 0 ) || ( iSample > iDifference ) )
		return( (double)m_iBytesRead );

	return( ( (double)m_iBytesRead / ( (double)iDifference / (double)iSample ) ) );
}

double Csock::GetAvgWrite( unsigned long long iSample )
{
	ev_tstamp iDifference = ev_now(EV_DEFAULT_UC) - m_tStartTime;

	// We need seconds, not milliseconds
	iSample /= 1000;

	if ( ( m_iBytesWritten == 0 ) || ( iSample > iDifference ) )
		return( (double)m_iBytesWritten );

	return( ( (double)m_iBytesWritten / ( (double)iDifference / (double)iSample ) ) );
}

u_short Csock::GetRemotePort()
{
	if ( m_iRemotePort > 0 )
		return( m_iRemotePort );

	int iSock = GetSock();

	if ( iSock >= 0 )
	{
		if( !GetIPv6() )
		{
			struct sockaddr_in mAddr;
			socklen_t mLen = sizeof( mAddr );
			if ( getpeername( iSock, (struct sockaddr *) &mAddr, &mLen ) == 0 )
				m_iRemotePort = ntohs( mAddr.sin_port );
		}
#ifdef HAVE_IPV6
		else
		{
			struct sockaddr_in6 mAddr;
			socklen_t mLen = sizeof( mAddr );
			if ( getpeername( iSock, (struct sockaddr *) &mAddr, &mLen ) == 0 )
				m_iRemotePort = ntohs( mAddr.sin6_port );
		}
#endif /* HAVE_IPV6 */
	}

	return( m_iRemotePort );
}

u_short Csock::GetLocalPort()
{
	if ( m_iLocalPort > 0 )
		return( m_iLocalPort );

	int iSock = GetSock();

	if ( iSock >= 0 )
	{
		if( !GetIPv6() )
		{
			struct sockaddr_in mLocalAddr;
			socklen_t mLocalLen = sizeof( mLocalAddr );
			if ( getsockname( iSock, (struct sockaddr *) &mLocalAddr, &mLocalLen ) == 0 )
				m_iLocalPort = ntohs( mLocalAddr.sin_port );
		}
#ifdef HAVE_IPV6
		else
		{
			struct sockaddr_in6 mLocalAddr;
			socklen_t mLocalLen = sizeof( mLocalAddr );
			if ( getsockname( iSock, (struct sockaddr *) &mLocalAddr, &mLocalLen ) == 0 )
				m_iLocalPort = ntohs( mLocalAddr.sin6_port );
		}
#endif /* HAVE_IPV6 */
	}

	return( m_iLocalPort );
}

u_short Csock::GetPort() { return( m_iport ); }
void Csock::SetPort( u_short iPort ) { m_iport = iPort; }
void Csock::Close( ECloseType eCloseType )
{
	m_eCloseType = eCloseType;
	if (m_Manager)
		m_Manager->AddAttentionSock(this);
}

bool Csock::GetSSL() { return( m_bssl ); }
void Csock::SetSSL( bool b ) { m_bssl = b; }

#ifdef HAVE_LIBSSL
void Csock::SetCipher( const CS_STRING & sCipher ) { m_sCipherType = sCipher; }
const CS_STRING & Csock::GetCipher() { return( m_sCipherType ); }
void Csock::SetPemLocation( const CS_STRING & sPemFile ) { m_sPemFile = sPemFile; }
const CS_STRING & Csock::GetPemLocation() { return( m_sPemFile ); }
void Csock::SetPemPass( const CS_STRING & sPassword ) { m_sPemPass = sPassword; }
const CS_STRING & Csock::GetPemPass() const { return( m_sPemPass ); }

int Csock::PemPassCB( char *buf, int size, int rwflag, void *pcSocket )
{
	Csock *pSock = (Csock *)pcSocket;
	const CS_STRING & sPassword = pSock->GetPemPass();
	memset( buf, '\0', size );
	strncpy( buf, sPassword.c_str(), size );
	buf[size-1] = '\0';
	return( strlen( buf ) );
}

int Csock::CertVerifyCB( int preverify_ok, X509_STORE_CTX *x509_ctx )
{
	/*
	 * A small quick example on how to get ahold of the Csock in the data portion of x509_ctx
	Csock *pSock = GetCsockFromCTX( x509_ctx );
	assert( pSock );
	cerr << pSock->GetRemoteIP() << endl;
	 */

	/* return 1 always for now, probably want to add some code for cert verification */
	return( 1 );
}

void Csock::SetSSLMethod( int iMethod ) { m_iMethod = iMethod; }
int Csock::GetSSLMethod() { return( m_iMethod ); }
void Csock::SetSSLObject( SSL *ssl ) { m_ssl = ssl; }
void Csock::SetCTXObject( SSL_CTX *sslCtx ) { m_ssl_ctx = sslCtx; }
void Csock::SetFullSSLAccept() { m_bFullsslAccept = true; }

SSL_SESSION * Csock::GetSSLSession()
{
	if ( m_ssl )
		return( SSL_get_session( m_ssl ) );

	return( NULL );
}
#endif /* HAVE_LIBSSL */

const CS_STRING & Csock::GetWriteBuffer() { return( m_sSend ); }
bool Csock::FullSSLAccept() { return ( m_bFullsslAccept ); }
bool Csock::SslIsEstablished() { return ( m_bsslEstablished ); }

bool Csock::ConnectInetd( bool bIsSSL, const CS_STRING & sHostname )
{
	if ( !sHostname.empty() )
		m_sSockName = sHostname;

	// set our hostname
	if ( m_sSockName.empty() )
	{
		struct sockaddr_in client;
		socklen_t clen = sizeof( client );
		if ( getpeername( 0, (struct sockaddr *)&client, &clen ) < 0 )
			m_sSockName = "0.0.0.0:0";
		else
		{
			stringstream s;
			s << inet_ntoa( client.sin_addr ) << ":" << ntohs( client.sin_port );
			m_sSockName = s.str();
		}
	}

	return( ConnectFD( 0, 1, m_sSockName, bIsSSL, INBOUND ) );
}

bool Csock::ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL, ETConn eDirection )
{
	if ( eDirection == LISTENER )
	{
		CS_DEBUG( "You can not use a LISTENER type here!" );
		return( false );
	}

	// set our socket type
	SetType( eDirection );

	// set the hostname
	m_sSockName = sName;

	// set the file descriptors
	SetRSock( iReadFD );
	SetWSock( iWriteFD );

	// set it up as non-blocking io
	set_non_blocking( GetRSock() );
	if (GetRSock() != GetWSock())
		set_non_blocking(GetWSock());

	if ( bIsSSL )
	{
		if ( ( eDirection == INBOUND ) && ( !AcceptSSL() ) )
			return( false );
		else if ( ( eDirection == OUTBOUND ) && ( !ConnectSSL() ) )
			return( false );
	}

	return( true );
}

#ifdef HAVE_LIBSSL
X509 *Csock::getX509()
{
	if ( m_ssl )
		return( SSL_get_peer_certificate( m_ssl ) );

	return( NULL );
}

CS_STRING Csock::GetPeerPubKey()
{
	CS_STRING sKey;

	SSL_SESSION *pSession = GetSSLSession();

	if ( ( pSession ) && ( pSession->peer ) )
	{
		EVP_PKEY *pKey = X509_get_pubkey( pSession->peer );
		if ( pKey )
		{
			char *hxKey = NULL;
			switch( pKey->type )
			{
				case EVP_PKEY_RSA:
				{
					hxKey = BN_bn2hex( pKey->pkey.rsa->n );
					break;
				}
				case EVP_PKEY_DSA:
				{
					hxKey = BN_bn2hex( pKey->pkey.dsa->pub_key );
					break;
				}
				default:
				{
					CS_DEBUG( "Not Prepared for Public Key Type [" << pKey->type << "]" );
					break;
				}
			}
			if ( hxKey )
			{
				sKey = hxKey;
				OPENSSL_free( hxKey );
			}
			EVP_PKEY_free( pKey );
		}
	}
	return( sKey );
}
unsigned int Csock::GetRequireClientCertFlags() { return( m_iRequireClientCertFlags ); }
void Csock::SetRequiresClientCert( bool bRequiresCert ) { m_iRequireClientCertFlags = ( bRequiresCert ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_PEER : 0 ); }

#endif /* HAVE_LIBSSL */

void Csock::SetParentSockName( const CS_STRING & sParentName ) { m_sParentName = sParentName; }
const CS_STRING & Csock::GetParentSockName() { return( m_sParentName ); }

void Csock::Cron()
{
	set<CCron *>::iterator it = m_sCrons.begin();

	while (it != m_sCrons.end())
	{
		CCron *pcCron = *it;

		if (!pcCron->isValid())
		{
			CS_Delete(pcCron);
			m_sCrons.erase(it++);
			// std::set::erase() only invalidates iterators
			// to the element being removed!
		} else
			it++;
	}
}

void Csock::AddCron(CCron * pcCron)
{
	m_sCrons.insert(pcCron);
}

void Csock::DelCron( const CS_STRING & sName, bool bDeleteAll, bool bCaseSensitive )
{
	std::set<CCron *>::iterator it = m_sCrons.begin();

	while (it != m_sCrons.end())
	{
		int (*Cmp)(const char *, const char *) = ( bCaseSensitive ? strcmp : strcasecmp );
		CCron *pcCron = *it;

		if (Cmp(pcCron->GetName().c_str(), sName.c_str()) == 0)
		{
			pcCron->Stop();
			m_sCrons.erase(it++);
			CS_Delete(pcCron);
			// iterators pointing to other elements than the
			// one being removed stay valid!

			if (!bDeleteAll)
				break;
		} else
			it++;
	}
}

void Csock::DelCronByAddr( CCron *pcCron )
{
	// First check if it's really in there, just because we can
	if (m_sCrons.find(pcCron) == m_sCrons.end())
		return;

	m_sCrons.erase(pcCron);
	CS_Delete(pcCron);
}

void Csock::EnableReadLine() { m_bEnableReadLine = true; }
void Csock::DisableReadLine() { m_bEnableReadLine = false; }

void Csock::ReachedMaxBuffer()
{
	std::cerr << "Warning, Max Buffer length Warning Threshold has been hit" << endl;
	std::cerr << "If you don't care, then set SetMaxBufferThreshold to 0" << endl;
}

int Csock::GetPending()
{
#ifdef HAVE_LIBSSL
	if( m_ssl )
		return( SSL_pending( m_ssl ) );
	else
		return( 0 );
#else
	return( 0 );
#endif /* HAVE_LIBSSL */
}

void Csock::SetConState(ECONState eState)
{
	m_eConState = eState;
	if (m_Manager && eState != CST_OK)
		m_Manager->AddAttentionSock(this);
}

int Csock::GetAddrInfo( const CS_STRING & sHostname, CSSockAddr & csSockAddr )
{
	return( ::GetAddrInfo( sHostname, this, csSockAddr ) );
}

int Csock::DNSLookup( EDNSLType eDNSLType )
{
	if ( eDNSLType == DNS_VHOST )
	{
		if ( m_sBindHost.empty() )
		{
			if ( GetConState() != CST_OK )
				SetConState(CST_DESTDNS); // skip binding, there is no vhost
			return( 0 );
		}

		m_bindhost.SinFamily();
		m_bindhost.SinPort( 0 );
	}

	int iRet = ETIMEDOUT;
	if ( eDNSLType == DNS_VHOST )
	{
		iRet = GetAddrInfo( m_sBindHost, m_bindhost );
#ifdef HAVE_IPV6
		if( m_bindhost.GetIPv6() )
		{
			SetAFRequire( CSSockAddr::RAF_INET6 );
		}
		else
		{
			SetAFRequire( CSSockAddr::RAF_INET );
		}
#endif /* HAVE_IPV6 */
	}
	else
	{
		iRet = GetAddrInfo( m_shostname, m_address );
	}

	if ( iRet == 0 )
	{
		if( !CreateSocksFD() )
		{
			return( ETIMEDOUT );
		}
		if ( GetConState() != CST_OK )
			SetConState(eDNSLType == DNS_VHOST ? CST_BINDVHOST : CST_CONNECT);
		return( 0 );
	}
	else if ( iRet == EAGAIN )
	{
		return( EAGAIN );
	}
	return( ETIMEDOUT );
}

bool Csock::SetupVHost()
{
	if ( m_sBindHost.empty() )
	{
		if ( GetConState() != CST_OK )
			SetConState(CST_DESTDNS);
		return( true );
	}
	int iRet = -1;
	if( !GetIPv6() )
		iRet = bind( GetRSock(), (struct sockaddr *) m_bindhost.GetSockAddr(), m_bindhost.GetSockAddrLen() );
#ifdef HAVE_IPV6
	else
		iRet = bind( GetRSock(), (struct sockaddr *) m_bindhost.GetSockAddr6(), m_bindhost.GetSockAddrLen6() );
#endif /* HAVE_IPV6 */

	if ( iRet == 0 )
	{
		if ( GetConState() != CST_OK )
			SetConState(CST_DESTDNS);
		return( true );
	}
	m_iCurBindCount++;
	if ( m_iCurBindCount > 3 )
	{
		CS_DEBUG( "Failure to bind to " << m_sBindHost );
		return( false );
	}

	return( true );
}

#ifdef HAVE_LIBSSL
void Csock::FREE_SSL()
{
	if ( m_ssl )
	{
		SSL_shutdown( m_ssl );
		SSL_free( m_ssl );
	}
	m_ssl = NULL;
}

void Csock::FREE_CTX()
{
	if ( m_ssl_ctx )
		SSL_CTX_free( m_ssl_ctx );

	m_ssl_ctx = NULL;
}

#endif /* HAVE_LIBSSL */

int Csock::SOCKET( bool bListen )
{
#ifdef HAVE_IPV6
	int iRet = socket( ( GetIPv6() ? PF_INET6 : PF_INET ), SOCK_STREAM, IPPROTO_TCP );
#else
	int iRet = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );
#endif /* HAVE_IPV6 */

	if ( iRet >= 0 ) {
		set_close_on_exec( iRet );

		if ( bListen ) {
			const int on = 1;

			if ( setsockopt( iRet, SOL_SOCKET, SO_REUSEADDR,
						(char *)&on, sizeof( on ) ) != 0 )
				PERROR( "setsockopt" );
		}
	} else
		PERROR( "socket" );

	return( iRet );
}

void Csock::Init( const CS_STRING & sHostname, u_short iport, int itimeout )
{
	ev_io_init(&m_read_io, EventCallback, -1, EV_READ);
	ev_io_init(&m_write_io, EventCallback, -1, EV_WRITE);
	ev_timer_init(&m_io_timeout, CheckTimeout, itimeout, itimeout);
	m_read_io.data = this;
	m_write_io.data = this;
	m_io_timeout.data = this;

	ev_timer_start(EV_DEFAULT_UC_ &m_io_timeout);

#ifdef HAVE_LIBSSL
	m_ssl = NULL;
	m_ssl_ctx = NULL;
	m_iRequireClientCertFlags = 0;
#endif /* HAVE_LIBSSL */
	SetSock(-1);
	m_bssl = false;
	m_bIsConnected = false;
	m_iport = iport;
	m_shostname = sHostname;
	m_sbuffer.clear();
	m_eCloseType = CLT_DONT;
	m_iMethod = SSL23;
	m_sCipherType = "ALL";
	m_bFullsslAccept = false;
	m_bsslEstablished = false;
	m_bEnableReadLine = false;
	m_iMaxStoredBufferLength = 1024;
	m_iConnType = INBOUND;
	m_iRemotePort = 0;
	m_iLocalPort = 0;
	m_iBytesRead = 0;
	m_iBytesWritten = 0;
	m_tStartTime = ev_now(EV_DEFAULT_UC);
	m_bPauseRead = false;
	m_iTimeoutType = TMO_ALL;
	m_eConState = CST_OK;	// default should be ok
	m_iCurBindCount = 0;
	m_bIsIPv6 = false;
	m_bSkipConnect = false;
	m_Manager = NULL;
}

void Csock::EventCallback(EV_P_ ev_io *io, int revents)
{
	Csock *pSock = (Csock *) io->data;
	if (revents & EV_WRITE) {
		if (!pSock->IsConnected() )
		{
			pSock->SetIsConnected(true);
			pSock->Connected();
		}
		pSock->Write("");
	}
	if (revents & EV_READ) {
		if (pSock->GetType() == LISTENER)
			pSock->DoAccept();
		else
			pSock->DoRead();
	}
}

void Csock::DoAccept()
{
	CS_STRING sHost;
	u_short port;
	int inSock = Accept( sHost, port );

	if (inSock == -1)
	{
#ifdef _WIN32
		if(GetSockError() != WSAEWOULDBLOCK)
#else /* _WIN32 */
		if(GetSockError() != EAGAIN)
#endif /* _WIN32 */
			SockError(GetSockError());

		return;
	}

	if ( TMO_ACCEPT & GetTimeoutType() )
		ResetTimer();	// let them now it got dinged

	// if we have a new sock, then add it
	Csock *NewpcSock = GetSockObj(sHost, port);

	if (!NewpcSock)
	{
		CS_CLOSE(inSock);
		return;
	}

	NewpcSock->SetType(INBOUND);
	NewpcSock->SetRSock(inSock);
	NewpcSock->SetWSock(inSock);
	NewpcSock->SetIPv6(GetIPv6());

	bool bAddSock = true;

	if (!m_Manager)
	{
		CS_DEBUG("Listening socket without a manager, dropping new connection :(");
		bAddSock = false;
	}

#ifdef HAVE_LIBSSL
	// is this ssl ?
	if ( GetSSL() && bAddSock )
	{
		NewpcSock->SetCipher( GetCipher() );
		NewpcSock->SetPemLocation( GetPemLocation() );
		NewpcSock->SetPemPass( GetPemPass() );
		NewpcSock->SetRequireClientCertFlags( GetRequireClientCertFlags() );
		bAddSock = NewpcSock->AcceptSSL();
	}
#endif /* HAVE_LIBSSL */

	if ( bAddSock )
	{
		// set the name of the listener
		NewpcSock->SetParentSockName( GetSockName() );
		if ( NewpcSock->GetSockName().empty() )
		{
			std::stringstream s;
			s << sHost << ":" << port;
			m_Manager->AddSock( NewpcSock,  s.str() );
		} else
			m_Manager->AddSock( NewpcSock, NewpcSock->GetSockName() );
	} else
		CS_Delete( NewpcSock );
}

void Csock::DoRead()
{
	bool bFirst = true;
	while (true) {
		// We read from the socket until there is no pending data
		// present anymore, that way we make sure we don't miss data in
		// openssl's read buffer.
		int iLen = GetPending();

		if (iLen == 0 && !bFirst)
			break;

		bFirst = false;

		if ( iLen <= 0 )
			iLen = CS_BLOCKSIZE;

		CSCharBuffer cBuff(iLen);

		int bytes = Read(cBuff(), iLen);

		if (bytes != READ_TIMEDOUT && bytes != READ_CONNREFUSED && !IsConnected() )
		{
			SetIsConnected(true);
			Connected();
		}

		switch( bytes )
		{
			case READ_EOF:
			{
				Close(CLT_NOW);
				break;
			}

			case READ_ERR:
			{
				SockError(GetSockError());
				Close(CLT_NOW);
				break;
			}

			case READ_EAGAIN:
				break;

			case READ_CONNREFUSED:
				ConnectionRefused();
				Close(CLT_NOW);
				break;

			case READ_TIMEDOUT:
				Timeout();
				Close(CLT_NOW);
				break;

			default:
			{
				if ( TMO_READ & GetTimeoutType() )
					ResetTimer();	// reset the timeout timer

				// Call ReadData() before PushBuff() so that it is called before the ReadLine() event - LD  07/18/05
				ReadData(cBuff(), bytes);
				PushBuff(cBuff(), bytes);
				break;
			}
		}
	}
}
