/**
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
* $Revision: 1.211 $
*/

// note to compile with win32 need to link to winsock2, using gcc its -lws2_32

#ifndef _HAS_CSOCKET_
#define _HAS_CSOCKET_
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/file.h>

#ifndef _WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#else

#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/timeb.h>
#define ECONNREFUSED WSAECONNREFUSED
#define EINPROGRESS WSAEINPROGRESS
#define ETIMEDOUT WSAETIMEDOUT
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define ECONNABORTED WSAECONNABORTED

#endif /* _WIN32 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif /* HAVE_LIBSSL */

#ifdef __sun
#include <strings.h>
#include <fcntl.h>
#endif /* __sun */

#include <iostream>
#include <string>
#include <set>

#include <ev.h>

#include "defines.h" // require this as a general rule, most projects have a defines.h or the like

#ifndef CS_STRING
#	ifdef _HAS_CSTRING_
#		define CS_STRING Cstring
#	else
#		define CS_STRING std::string
#	endif	/* _HAS_CSTRING_ */
#endif /* CS_STRING */

#ifndef CS_DEBUG
#ifdef __DEBUG__
#	define CS_DEBUG( f ) std::cerr << __FILE__ << ":" << __LINE__ << " " << f << std::endl
#else
#	define CS_DEBUG(f)	(void)0
#endif /* __DEBUG__ */
#endif /* CS_DEBUG */

#ifndef PERROR
#ifdef __DEBUG__
#	define PERROR( f ) __Perror( f, __FILE__, __LINE__ )
#else
#	define PERROR( f )	(void)0
#endif /* __DEBUG__ */
#endif /* PERROR */

#ifndef _NO_CSOCKET_NS // some people may not want to use a namespace
namespace Csocket
{
#endif /* _NO_CSOCKET_NS */


/**
 * @class CSCharBuffer
 * @brief ease of use self deleting char * class
 */
class CSCharBuffer
{
public:
	CSCharBuffer( size_t iSize )
	{
		m_pBuffer = (char *)malloc( iSize );
	}
	~CSCharBuffer()
	{
		free( m_pBuffer );
	}
	char * operator()() { return( m_pBuffer ); }

private:
	char *	m_pBuffer;
};

class CSSockAddr
{
public:
	CSSockAddr()
	{
		m_bIsIPv6 = false;
		memset( (struct sockaddr_in *)&m_saddr, '\0', sizeof( m_saddr ) );
#ifdef HAVE_IPV6
		memset( (struct sockaddr_in6 *)&m_saddr6, '\0', sizeof( m_saddr6 ) );
#endif /* HAVE_IPV6 */
		m_iAFRequire = RAF_ANY;
	}
	virtual ~CSSockAddr() {}


	enum EAFRequire
	{
		RAF_ANY		= PF_UNSPEC,
#ifdef HAVE_IPV6
		RAF_INET6	= AF_INET6,
#endif /* HAVE_IPV6 */
		RAF_INET	= AF_INET
	};

	void SinFamily()
	{
#ifdef HAVE_IPV6
		if( m_bIsIPv6 )
		{
			m_saddr6.sin6_family = PF_INET6;
			return;
		}
#endif /* HAVE_IPV6 */
		m_saddr.sin_family = PF_INET;
	}
	void SinPort( u_short iPort )
	{
#ifdef HAVE_IPV6
		if( m_bIsIPv6 )
		{
			m_saddr6.sin6_port = htons( iPort );
			return;
		}
#endif /* HAVE_IPV6 */
		m_saddr.sin_port = htons( iPort );
	}

	void SetIPv6( bool b )
	{
#ifndef HAVE_IPV6
		if( b )
		{
			CS_DEBUG( "-DHAVE_IPV6 must be set during compile time to enable this feature" );
			m_bIsIPv6 = false;
			return;
		}
#endif /* HAVE_IPV6 */
		m_bIsIPv6 = b;
		SinFamily();
	}
	bool GetIPv6() const { return( m_bIsIPv6 ); }


	socklen_t GetSockAddrLen() { return( sizeof( m_saddr ) ); }
	sockaddr_in * GetSockAddr() { return( &m_saddr ); }
	in_addr * GetAddr() { return( &(m_saddr.sin_addr) ); }
#ifdef HAVE_IPV6
	socklen_t GetSockAddrLen6() { return( sizeof( m_saddr6 ) ); }
	sockaddr_in6 * GetSockAddr6() { return( &m_saddr6 ); }
	in6_addr * GetAddr6() { return( &(m_saddr6.sin6_addr) ); }
#endif /* HAVE_IPV6 */

	void SetAFRequire( EAFRequire iWhich ) { m_iAFRequire = iWhich; }
	EAFRequire GetAFRequire() const { return( m_iAFRequire ); }

private:
	bool			m_bIsIPv6;
	sockaddr_in		m_saddr;
#ifdef HAVE_IPV6
	sockaddr_in6	m_saddr6;
#endif /* HAVE_IPV6 */
	EAFRequire		m_iAFRequire;
};

class Csock;

class CSocketManagerBase
{
public:
	CSocketManagerBase ()
	{
	}

	virtual ~CSocketManagerBase()
	{
	}

	virtual void AddSock(Csock *pcSock, const CS_STRING & sSockName) = 0;

	// The socket is already added to the manager but it needs some
	// attention by TSocketManagerBase::Prepare()
	virtual void AddAttentionSock(Csock *pcSock) = 0;
};

/**
 * @brief this function is a wrapper around gethostbyname and getaddrinfo (for ipv6)
 *
 * in the event this code is using ipv6, it calls getaddrinfo, and it tries to start the connection on each iteration
 * in the linked list returned by getaddrinfo. if pSock is not NULL the following behavior happens.
 * - if pSock is a listener, or if the connect state is in a bind vhost state (to be used with bind) AI_PASSIVE is sent to getaddrinfo
 * - if pSock is an outbound connection, AI_ADDRCONFIG and the connection is started from within this function.
 * getaddrinfo might return multiple (possibly invalid depending on system configuration) ip addresses, so connect needs to try them all.
 * A classic example of this is a hostname that resolves to both ipv4 and ipv6 ip's. You still need to call Connect (and ConnectSSL) to finish
 * up the connection state
 * - NOTE ... Once threading is reimplemented, this function will spin off a thread to resolve and return EAGAIN until its done.
 *
 * @param sHostname the host to resolve
 * @param pSock the sock being setup, this option can be NULL, if it is null csSockAddr is only setup
 * @param csSockAddr the struct that sockaddr data is being copied to
 * @return 0 on success, otherwise an error. EAGAIN if this needs to be called again at a later time, ETIMEDOUT if no host is found
 */
int GetAddrInfo( const CS_STRING & sHostname, Csock *pSock, CSSockAddr & csSockAddr );

//! used to retrieve the context position of the socket to its associated ssl connection. Setup once in InitSSL() via SSL_get_ex_new_index
int GetCsockClassIdx();

#ifdef HAVE_LIBSSL
//! returns the sock object associated to the particular context. returns NULL on failure or if not available
Csock *GetCsockFromCTX( X509_STORE_CTX *pCTX );
#endif /* HAVE_LIBSSL */


const u_int CS_BLOCKSIZE = 4096;
template <class T> inline void CS_Delete( T * & p ) { if( p ) { delete p; p = NULL; } }

#ifdef HAVE_LIBSSL
enum ECompType
{
	CT_NONE	= 0,
	CT_ZLIB	= 1,
	CT_RLE	= 2
};

void SSLErrors( const char *filename, u_int iLineNum );

/**
 * @brief You HAVE to call this in order to use the SSL library, calling InitCsocket() also calls this
 * so unless you need to call InitSSL for a specific reason call InitCsocket()
 * @return true on success
 */

bool InitSSL( ECompType eCompressionType = CT_NONE );

#endif /* HAVE_LIBSSL */

/**
 * This does all the csocket initialized inclusing InitSSL() and win32 specific initializations, only needs to be called once
 */
bool InitCsocket();
/**
 * Shutdown and release global allocated memory
 */
void ShutdownCsocket();

//! @todo need to make this sock specific via getsockopt
inline int GetSockError()
{
#ifdef _WIN32
	return( WSAGetLastError() );
#else
	return( errno );
#endif /* _WIN32 */
}

//! wrappers for FD_SET and such to work in templates.
inline void TFD_ZERO( fd_set *set )
{
	FD_ZERO( set );
}

inline void TFD_SET( u_int iSock, fd_set *set )
{
	FD_SET( iSock, set );
}

inline bool TFD_ISSET( u_int iSock, fd_set *set )
{
	if ( FD_ISSET( iSock, set ) )
		return( true );

	return( false );
}

inline void TFD_CLR( u_int iSock, fd_set *set )
{
	FD_CLR( iSock, set );
}

void __Perror( const CS_STRING & s, const char *pszFile, unsigned int iLineNo );


/**
* @class CCron
* @brief this is the main cron job class
*
* You should derive from this class, and override RunJob() with your code
* @author Jim Hull <imaginos@imaginos.net>
*/

class CCron
{
public:
	CCron();
	virtual ~CCron();

	/**
	 * @param TimeSequence	how often to run in seconds
	 * @param iMaxCycles		how many times to run, 0 makes it run forever
	 */
	void StartMaxCycles( int TimeSequence, u_int iMaxCycles );

	//! starts and runs infinity amount of times
	void Start( int TimeSequence, bool bFirstCall = false );

	//! call this to turn off your cron, it will be removed
	void Stop();

	int GetInterval() const;
	u_int GetMaxCycles() const;
	u_int GetCyclesLeft() const;

	//! returns true if cron is active
	bool isValid();

	const CS_STRING & GetName() const;
	void SetName( const CS_STRING & sName );

public:

	//! this is the method you should override
	virtual void RunJob() = 0;

private:
	static void TimerCallback(EV_P_ ev_timer *timer, int revents);

	ev_timer	m_timer;
	u_int		m_iMaxCycles, m_iCycles;
	CS_STRING	m_sName;
};

#ifdef HAVE_LIBSSL
typedef int (*FPCertVerifyCB)( int, X509_STORE_CTX * );
#endif /* HAVE_LIBSSL */

/**
* @class Csock
* @brief Basic Socket Class
* The most basic level socket class
* You can use this class directly for quick things
* or use the socket manager
* @see TSocketManager
* @author Jim Hull <imaginos@imaginos.net>
*/
class Csock
{
public:
	//! default constructor, sets a timeout of 60 seconds
	Csock( int itimeout = 60 );
	/**
	* Advanced constructor, for creating a simple connection
	*
	* @param sHostname the hostname your are connecting to
	* @param iport the port you are connectint to
	* @param itimeout how long to wait before ditching the connection, default is 60 seconds
	*/
	Csock( const CS_STRING & sHostname, u_short iport, int itimeout = 60 );

	//! override this for accept sockets
	virtual Csock *GetSockObj( const CS_STRING & sHostname, u_short iPort );

	virtual ~Csock();

	/**
	 * @brief in the event you pass this class to Copy(), you MUST call this function or
	 * on the original Csock other wise bad side effects will happen (double deletes, weird sock closures, etc)
	 * if you call this function and have not handled the internal pointers, other bad things can happend (memory leaks, fd leaks, etc)
	 * the whole point of this function is to allow this class to go away without shutting down
	 */
	virtual void Dereference();
	//! use this to copy a sock from one to the other, override it if you have special needs in the event of a copy
	virtual void Copy( const Csock & cCopy );

	enum ETConn
	{
		OUTBOUND			= 0,		//!< outbound connection
		LISTENER			= 1,		//!< a socket accepting connections
		INBOUND				= 2			//!< an inbound connection, passed from LISTENER
	};

	enum EFRead
	{
		READ_EOF			= 0,			//!< End Of File, done reading
		READ_ERR			= -1,			//!< Error on the socket, socket closed, done reading
		READ_EAGAIN			= -2,			//!< Try to get data again
		READ_CONNREFUSED	= -3,			//!< Connection Refused
		READ_TIMEDOUT		= -4			//!< Connection timed out
	};

	enum ESSLMethod
	{
		SSL23				= 0,
		SSL2				= 2,
		SSL3				= 3,
		TLS1				= 4
	};

	enum ECONState
	{
		CST_START		= 0,
		CST_DNS			= CST_START,
		CST_BINDVHOST	= 1,
		CST_DESTDNS		= 2,
		CST_CONNECT		= 3,
		CST_CONNECTSSL	= 4,
		CST_OK			= 5
	};

	enum ECloseType
	{
		CLT_DONT			= 0, //! don't close DER
		CLT_NOW				= 1, //! close immediatly
		CLT_AFTERWRITE		= 2,  //! close after finishing writing the buffer
		CLT_DEREFERENCE		= 3	 //! used after copy in Csock::Dereference() to cleanup a sock thats being shutdown
	};

	Csock & operator<<( const CS_STRING & s );
	Csock & operator<<( std::ostream & ( *io )( std::ostream & ) );
	Csock & operator<<( int i );
	Csock & operator<<( unsigned int i );
	Csock & operator<<( long i );
	Csock & operator<<( unsigned long i );
	Csock & operator<<( unsigned long long i );
	Csock & operator<<( float i );
	Csock & operator<<( double i );

	/**
	* Create the connection
	*
	* @param sBindHost the ip you want to bind to locally
	* @param bSkipSetup if true, setting up the vhost etc is skipped
	* @return true on success
	*/
	virtual bool Connect( const CS_STRING & sBindHost = "", bool bSkipSetup = false );

	/**
	* Listens for connections
	*
	* @param iPort the port to listen on
	* @param iMaxConns the maximum amount of connections to allow
	* @param sBindHost the vhost on which to listen
	* @param iTimeout i dont know what this does :(
	*/
	virtual bool Listen( u_short iPort, int iMaxConns = SOMAXCONN, const CS_STRING & sBindHost = "", u_int iTimeout = 0 );

	//! Accept an inbound connection, this is used internally
	virtual int Accept( CS_STRING & sHost, u_short & iRPort );

	//! Accept an inbound SSL connection, this is used internally and called after Accept
	virtual bool AcceptSSL();

	//! This sets up the SSL Client, this is used internally
	virtual bool SSLClientSetup();

	//! This sets up the SSL Server, this is used internally
	virtual bool SSLServerSetup();

	/**
	* Create the SSL connection
	*
	* @param sBindhost the ip you want to bind to locally
	* @return true on success
	*/
	virtual bool ConnectSSL( const CS_STRING & sBindhost = "" );


	/**
	* Write data to the socket
	* if not all of the data is sent, it will be stored on
	* an internal buffer, and tried again with next call to Write
	* if the socket is blocking, it will send everything, its ok to check ernno after this (nothing else is processed)
	*
	* @param data the data to send
	* @param len the length of data
	*
	*/
	virtual bool Write( const char *data, int len );

	/**
	* convience function
	* @see Write( const char *, int )
	*/
	virtual bool Write( const CS_STRING & sData );

	/**
	* Read from the socket
	* Just pass in a pointer, big enough to hold len bytes
	*
	* @param data the buffer to read into
	* @param len the size of the buffer
	*
	* @return
	* Returns READ_EOF for EOF
	* Returns READ_ERR for ERROR
	* Returns READ_EAGAIN for Try Again ( EAGAIN )
	* Returns READ_CONNREFUSED for connection refused
	* Returns READ_TIMEDOUT for a connection that timed out at the TCP level
	* Otherwise returns the bytes read into data
	*/
	virtual int Read( char *data, int len );
	CS_STRING GetLocalIP();
	CS_STRING GetRemoteIP();

	//! Tells you if the socket is connected
	virtual bool IsConnected();
	//! Sets the sock, telling it its connected (internal use only)
	virtual void SetIsConnected( bool b );

	int GetRSock() const;
	void SetRSock( int iSock );
	int GetWSock() const;
	void SetWSock( int iSock );

	void SetSock( int iSock );
	int GetSock() const;

	//! resets the time counter, this is virtual in the event you need an event on the timer being Reset
	virtual void ResetTimer();

	//! will pause/unpause reading on this socket
	void PauseRead();
	void UnPauseRead();
	bool IsReadPaused();
	/**
	* this timeout isn't just connection timeout, but also timeout on
	* NOT recieving data, to disable this set it to 0
	* then the normal TCP timeout will apply (basically TCP will kill a dead connection)
	* Set the timeout, set to 0 to never timeout
	*/
	enum
	{
		TMO_READ	= 1,
		TMO_WRITE	= 2,
		TMO_ACCEPT	= 4,
		TMO_ALL		= TMO_READ|TMO_WRITE|TMO_ACCEPT
	};

	//! Currently this uses the same value for all timeouts, and iTimeoutType merely states which event will be checked
	//! for timeouts
	void SetTimeout( int iTimeout, u_int iTimeoutType = TMO_ALL );
	void SetTimeoutType( u_int iTimeoutType );
	int GetTimeout() const;
	u_int GetTimeoutType() const;

	/**
	* pushes data up on the buffer, if a line is ready
	* it calls the ReadLine event
	*/
	virtual void PushBuff( const char *data, int len, bool bStartAtZero = false );

	//! This gives access to the internal read buffer, if your
	//! not going to use ReadLine(), then you may want to clear this out
	//! (if its binary data and not many '\\n')
	CS_STRING & GetInternalReadBuffer();

	//! This gives access to the internal write buffer.
	//! If you want to check if the send queue fills up, check here.
	CS_STRING & GetInternalWriteBuffer();

	//! sets the max buffered threshold when EnableReadLine() is enabled
	void SetMaxBufferThreshold( u_int iThreshold );
	u_int GetMaxBufferThreshold() const;

	//! Returns the connection type from enum eConnType
	int GetType() const;
	void SetType( int iType );

	//! Returns a reference to the socket name
	const CS_STRING & GetSockName() const;
	void SetSockName( const CS_STRING & sName );

	//! Returns a reference to the host name
	const CS_STRING & GetHostName() const;
	void SetHostName( const CS_STRING & sHostname );


	//! Gets the starting time of this socket
	ev_tstamp GetStartTime() const;

	//! Gets the amount of data read during the existence of the socket
	unsigned long long GetBytesRead() const;
	void ResetBytesRead();

	//! Gets the amount of data written during the existence of the socket
	unsigned long long GetBytesWritten() const;
	void ResetBytesWritten();

	//! Get Avg Read Speed in sample milliseconds (default is 1000 milliseconds or 1 second)
	double GetAvgRead( unsigned long long iSample = 1000 );

	//! Get Avg Write Speed in sample milliseconds (default is 1000 milliseconds or 1 second)
	double GetAvgWrite( unsigned long long iSample = 1000 );

	//! Returns the remote port
	u_short GetRemotePort();

	//! Returns the local port
	u_short GetLocalPort();

	//! Returns the port
	u_short GetPort();
	void SetPort( u_short iPort );

	//! just mark us as closed, the parent can pick it up
	void Close( ECloseType eCloseType = CLT_NOW );
	//! returns int of type to close @see ECloseType
	ECloseType GetCloseType() { return( m_eCloseType ); }
	bool IsClosed() { return( GetCloseType() != CLT_DONT ); }

	//! if this connection type is ssl or not
	bool GetSSL();
	void SetSSL( bool b );

#ifdef HAVE_LIBSSL
	//! Set the cipher type ( openssl cipher [to see ciphers available] )
	void SetCipher( const CS_STRING & sCipher );
	const CS_STRING & GetCipher();

	//! Set the pem file location
	void SetPemLocation( const CS_STRING & sPemFile );
	const CS_STRING & GetPemLocation();
	void SetPemPass( const CS_STRING & sPassword );
	const CS_STRING & GetPemPass() const;
	static int PemPassCB( char *buf, int size, int rwflag, void *pcSocket );
	static int CertVerifyCB( int preverify_ok, X509_STORE_CTX *x509_ctx );

	//! Set the SSL method type
	void SetSSLMethod( int iMethod );
	int GetSSLMethod();

	void SetSSLObject( SSL *ssl );
	void SetCTXObject( SSL_CTX *sslCtx );
	void SetFullSSLAccept();
	SSL_SESSION * GetSSLSession();

	void SetCertVerifyCB( FPCertVerifyCB pFP ) { m_pCerVerifyCB = pFP; }
#endif /* HAVE_LIBSSL */

	//! Get the send buffer
	const CS_STRING & GetWriteBuffer();

	//! is SSL_accept finished ?
	bool FullSSLAccept();
	//! is the ssl properly finished (from write no error)
	bool SslIsEstablished();

	//! Use this to bind this socket to inetd
	bool ConnectInetd( bool bIsSSL = false, const CS_STRING & sHostname = "" );

	//! Tie this guy to an existing real file descriptor
	bool ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL = false, ETConn eDirection = INBOUND );

	//! Get the peer's X509 cert
#ifdef HAVE_LIBSSL
	X509 *getX509();

	//! Returns The Peers Public Key
	CS_STRING GetPeerPubKey();
	unsigned int GetRequireClientCertFlags();
	//! legacy, deprecated @see SetRequireClientCertFlags
	void SetRequiresClientCert( bool bRequiresCert );
	//! bitwise flags, 0 means don't require cert, SSL_VERIFY_PEER verifies peers, SSL_VERIFY_FAIL_IF_NO_PEER_CERT will cause the connection to fail if no cert 
	void SetRequireClientCertFlags( unsigned int iRequireClientCertFlags ) { m_iRequireClientCertFlags = iRequireClientCertFlags; }

#endif /* HAVE_LIBSSL */

	//! Set The INBOUND Parent sockname
	virtual void SetParentSockName( const CS_STRING & sParentName );
	const CS_STRING & GetParentSockName();

	//! This has a garbage collecter, and is used internall to call the jobs
	virtual void Cron();

	//! insert a newly created cron
	virtual void AddCron( CCron * pcCron );
	/**
	 * @brief deletes a cron by name
	 * @param sName the name of the cron
	 * @param bDeleteAll delete all crons that match sName
	 * @param bCaseSensitive use strcmp or strcasecmp
	 */
	virtual void DelCron( const CS_STRING & sName, bool bDeleteAll = true, bool bCaseSensitive = true );
	//! delete cron by address
	virtual void DelCronByAddr( CCron *pcCron );

	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	* Connected event
	*/
	virtual void Connected() {}
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	* Disconnected event
	*/
	virtual void Disconnected() {}
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	* Sock Timed out event
	*/
	virtual void Timeout() {}
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	* Ready to read data event
	*/
	virtual void ReadData( const char *data, int len ) {}
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks.
	*  With ReadLine, if your not going to use it IE a data stream, @see EnableReadLine()
	*
	* Ready to Read a full line event
	*/
	virtual void ReadLine( const CS_STRING & sLine ) {}
	//! set the value of m_bEnableReadLine to true, we don't want to store a buffer for ReadLine, unless we want it
	void EnableReadLine();
	void DisableReadLine();
	//! returns the value of m_bEnableReadLine, if ReadLine is enabled
	bool HasReadLine() const { return( m_bEnableReadLine ); }

	/**
	 * Override these functions for an easy interface when using the Socket Manager
	 * Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	 * as the Socket Manager calls most of these callbacks
	 * This WARNING event is called when your buffer for readline exceeds the warning threshold
	 * and triggers this event. Either Override it and do nothing, or SetMaxBufferThreshold()
	 * This event will only get called if m_bEnableReadLine is enabled
	 */
	virtual void ReachedMaxBuffer();
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	* A sock error occured event
	*/
	virtual void SockError( int iErrno ) {}
	/**
	* Override these functions for an easy interface when using the Socket Manager
	* Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	* as the Socket Manager calls most of these callbacks
	*
	*
	* Incoming Connection Event
	* return false and the connection will fail
	* default returns true
	*/
	virtual bool ConnectionFrom( const CS_STRING & sHost, u_short iPort ) { return( true ); }

	/**
	 * Override these functions for an easy interface when using the Socket Manager
	 * Don't bother using these callbacks if you are using this class directly (without Socket Manager)
	 * as the Socket Manager calls most of these callbacks
	 *
	 * Connection Refused Event
	 *
	 */
	virtual void ConnectionRefused() {}
	/**
	 * This gets called every iteration of TSocketManager::Select() if the socket is ReadPaused
	 */
	virtual void ReadPaused() {}

#ifdef HAVE_LIBSSL
	/**
	 * Gets called immediatly after the m_ssl member is setup and initialized, useful if you need to assign anything
	 * to this ssl session via SSL_set_ex_data
	 */
	virtual void SSLFinishSetup( SSL *pSSL ) {}
#endif /* HAVE_LIBSSL */


	//! return how long it has been (in seconds) since the last read or successful write
	int GetTimeSinceLastDataTransaction( time_t iNow = 0 )
	{
		ev_tstamp time_left = ev_timer_remaining(EV_DEFAULT_UC_ &m_io_timeout);

		// If it will fire in 3s and timeout is 10s, then obviously the
		// timeout was last reset 7s ago.
		ev_tstamp last = GetTimeout() - time_left;

		// Just to be safe
		if (last < 0)
			return 0;
		return last;
	}

	//! return the data imediatly ready for read
	virtual int GetPending();

	//////////////////////////
	// Connection State Stuff
	//! returns the current connection state
	ECONState GetConState() const { return( m_eConState ); }
	//! sets the connection state to eState
	void SetConState( ECONState eState );

	//! grabs fd's for the sockets
	bool CreateSocksFD()
	{
		if( GetRSock() != -1 )
			return( true );

		SetRSock(SOCKET());
		if ( GetRSock() == -1 )
			return( false );

		SetWSock(GetRSock());

		m_address.SinFamily();
		m_address.SinPort( m_iport );

		return( true );
	}

	const CS_STRING & GetBindHost() const { return( m_sBindHost ); }
	void SetBindHost( const CS_STRING & sBindHost ) { m_sBindHost = sBindHost; }

	enum EDNSLType
	{
		DNS_VHOST,
		DNS_DEST
	};

	/**
	 * nonblocking dns lookup (when -pthread is set to compile)
	 * @return 0 for success, EAGAIN to check back again (same arguments as before), ETIMEDOUT on failure
	 */
	int DNSLookup( EDNSLType eDNSLType );

	//! this is only used on outbound connections, listeners bind in a different spot
	bool SetupVHost();

	bool GetIPv6() const { return( m_bIsIPv6 ); }
	void SetIPv6( bool b )
	{
		m_bIsIPv6 = b;
		m_address.SetIPv6( b );
		m_bindhost.SetIPv6( b );
	}

	void SetAFRequire( CSSockAddr::EAFRequire iAFRequire )
	{
		m_address.SetAFRequire( iAFRequire );
		m_bindhost.SetAFRequire( iAFRequire );
	}

	//! returns a const reference to the crons associated to this socket
	const std::set<CCron *> & GetCrons() const { return( m_sCrons ); }

	void SetSkipConnect( bool b ) { m_bSkipConnect = b; }

	/**
	 * @brief override this call with your own DNS lookup method if you have one. By default this function is blocking
	 * @param sHostname the hostname to resolve
	 * @param csSockAddr the destination sock address info @see CSSockAddr
	 * @return 0 on success, ETIMEDOUT if no lookup was found, EAGAIN if you should check again later for an answer
	 */
	virtual int GetAddrInfo( const CS_STRING & sHostname, CSSockAddr & csSockAddr );

	void SetManager(CSocketManagerBase *Manager) { m_Manager = Manager; }

private:
	//! making private for safety
	Csock( const Csock & cCopy ) {}

	//! closes the socket if it has timed out
	static void CheckTimeout(EV_P_ ev_timer *timeout, int revents);

	static void EventCallback(EV_P_ ev_io *io, int revents);
	void DoAccept();
	void DoRead();

	ev_io	m_read_io, m_write_io;
	ev_timer m_io_timeout;

	// NOTE! if you add any new members, be sure to add them to Copy()
	u_short		m_iport, m_iRemotePort, m_iLocalPort;
	int			m_iConnType, m_iMethod;
	bool		m_bssl, m_bIsConnected, m_bFullsslAccept;
	bool		m_bsslEstablished, m_bEnableReadLine, m_bPauseRead;
	CS_STRING	m_shostname, m_sbuffer, m_sSockName, m_sPemFile, m_sCipherType, m_sParentName;
	CS_STRING	m_sSend, m_sPemPass, m_sLocalIP, m_sRemoteIP;
	ECloseType	m_eCloseType;

	unsigned long long	m_iBytesRead, m_iBytesWritten;
	unsigned int		m_iMaxStoredBufferLength, m_iTimeoutType;
	ev_tstamp		m_tStartTime;

	CSSockAddr 		m_address, m_bindhost;
	bool			m_bIsIPv6, m_bSkipConnect;

#ifdef HAVE_LIBSSL
	CS_STRING			m_sSSLBuffer;
	SSL 				*m_ssl;
	SSL_CTX				*m_ssl_ctx;
	unsigned int		m_iRequireClientCertFlags;

	FPCertVerifyCB		m_pCerVerifyCB;

	void FREE_SSL();
	void FREE_CTX();

#endif /* HAVE_LIBSSL */

	std::set<CCron *>		m_sCrons;

	//! Create the socket
	int SOCKET( bool bListen = false );
	void Init( const CS_STRING & sHostname, u_short iport, int itimeout = 60 );


	// Connection State Info
	ECONState		m_eConState;
	CS_STRING		m_sBindHost;
	u_int			m_iCurBindCount;

	CSocketManagerBase*	m_Manager;
};

/**
 * @class CSConnection
 * @brief options for creating a connection
 */
class CSConnection
{
public:
	/**
	 * @param sHostname hostname to connect to
	 * @param iPort port to connect to
	 * @param iTimeout connection timeout
	 */
	CSConnection( const CS_STRING & sHostname, u_short iPort, int iTimeout = 60 )
	{
		m_sHostname = sHostname;
		m_iPort = iPort;
		m_iTimeout = iTimeout;
		m_bIsSSL = false;
#ifdef HAVE_LIBSSL
		m_sCipher = "HIGH";
#endif /* HAVE_LIBSSL */
		m_iAFrequire = CSSockAddr::RAF_ANY;
	}
	virtual ~CSConnection() {}

	const CS_STRING & GetHostname() const { return( m_sHostname ); }
	const CS_STRING & GetSockName() const { return( m_sSockName ); }
	const CS_STRING & GetBindHost() const { return( m_sBindHost ); }
	u_short GetPort() const { return( m_iPort ); }
	int GetTimeout() const { return( m_iTimeout ); }
	bool GetIsSSL() const { return( m_bIsSSL ); }
	CSSockAddr::EAFRequire GetAFRequire() const { return( m_iAFrequire ); }

#ifdef HAVE_LIBSSL
	const CS_STRING & GetCipher() const { return( m_sCipher ); }
	const CS_STRING & GetPemLocation() const { return( m_sPemLocation ); }
	const CS_STRING & GetPemPass() const { return( m_sPemPass ); }
#endif /* HAVE_LIBSSL */

	//! sets the hostname to connect to
	void SetHostname( const CS_STRING & s ) { m_sHostname = s; }
	//! sets the name of the socket, used for reference, ie in FindSockByName()
	void SetSockName( const CS_STRING & s ) { m_sSockName = s; }
	//! sets the hostname to bind to (vhost support)
	void SetBindHost( const CS_STRING & s ) { m_sBindHost = s; }
	//! sets the port to connect to
	void SetPort( u_short i ) { m_iPort = i; }
	//! sets the connection timeout
	void SetTimeout( int i ) { m_iTimeout = i; }
	//! set to true to enable SSL
	void SetIsSSL( bool b ) { m_bIsSSL = b; }
	//! sets the AF family type required
	void SetAFRequire( CSSockAddr::EAFRequire iAFRequire ) { m_iAFrequire = iAFRequire; }

#ifdef HAVE_LIBSSL
	//! set the cipher strength to use, default is HIGH
	void SetCipher( const CS_STRING & s ) { m_sCipher = s; }
	//! set the location of the pemfile
	void SetPemLocation( const CS_STRING & s ) { m_sPemLocation = s; }
	//! set the pemfile pass
	void SetPemPass( const CS_STRING & s ) { m_sPemPass = s; }
#endif /* HAVE_LIBSSL */

protected:
	CS_STRING	m_sHostname, m_sSockName, m_sBindHost;
	u_short		m_iPort;
	int			m_iTimeout;
	bool		m_bIsSSL;
	CSSockAddr::EAFRequire	m_iAFrequire;
#ifdef HAVE_LIBSSL
	CS_STRING	m_sPemLocation, m_sPemPass, m_sCipher;
#endif /* HAVE_LIBSSL */
};

class CSSSLConnection : public CSConnection
{
public:
	CSSSLConnection( const CS_STRING & sHostname, u_short iPort, int iTimeout = 60 ) :
		CSConnection( sHostname, iPort, iTimeout )
	{
		SetIsSSL( true );
	}
};


/**
 * @class CSListener
 * @brief options container to create a listener
 */
class CSListener
{
public:
	/**
	 * @param iPort port to listen on. Set to 0 to listen on a random port
	 * @param sBindHost host to bind to
	 */
	CSListener( u_short iPort, const CS_STRING & sBindHost = "" )
	{
		m_iPort = iPort;
		m_sBindHost = sBindHost;
		m_bIsSSL = false;
		m_iMaxConns = SOMAXCONN;
		m_iTimeout = 0;
		m_iAFrequire = CSSockAddr::RAF_ANY;
#ifdef HAVE_LIBSSL
		m_sCipher = "HIGH";
		m_iRequireCertFlags = 0;
#endif /* HAVE_LIBSSL */
	}
	virtual ~CSListener() {}

	u_short GetPort() const { return( m_iPort ); }
	const CS_STRING & GetSockName() const { return( m_sSockName ); }
	const CS_STRING & GetBindHost() const { return( m_sBindHost ); }
	bool GetIsSSL() const { return( m_bIsSSL ); }
	int GetMaxConns() const { return( m_iMaxConns ); }
	u_int GetTimeout() const { return( m_iTimeout ); }
	CSSockAddr::EAFRequire GetAFRequire() const { return( m_iAFrequire ); }
#ifdef HAVE_LIBSSL
	const CS_STRING & GetCipher() const { return( m_sCipher ); }
	const CS_STRING & GetPemLocation() const { return( m_sPemLocation ); }
	const CS_STRING & GetPemPass() const { return( m_sPemPass ); }
	unsigned int GetRequireClientCertFlags() const { return( m_iRequireCertFlags ); }
#endif /* HAVE_LIBSSL */

	//! sets the port to listen on. Set to 0 to listen on a random port
	void SetPort( u_short iPort ) { m_iPort = iPort; }
	//! sets the sock name for later reference (ie FindSockByName)
	void SetSockName( const CS_STRING & sSockName ) { m_sSockName = sSockName; }
	//! sets the host to bind to
	void SetBindHost( const CS_STRING & sBindHost ) { m_sBindHost = sBindHost; }
	//! set to true to enable SSL
	void SetIsSSL( bool b ) { m_bIsSSL = b; }
	//! set max connections as called by accept()
	void SetMaxConns( int i ) { m_iMaxConns = i; }
	//! sets the listen timeout. The listener class will close after timeout has been reached if not 0
	void SetTimeout( u_int i ) { m_iTimeout = i; }
	//! sets the AF family type required
	void SetAFRequire( CSSockAddr::EAFRequire iAFRequire ) { m_iAFrequire = iAFRequire; }

#ifdef HAVE_LIBSSL
	//! set the cipher strength to use, default is HIGH
	void SetCipher( const CS_STRING & s ) { m_sCipher = s; }
	//! set the location of the pemfile
	void SetPemLocation( const CS_STRING & s ) { m_sPemLocation = s; }
	//! set the pemfile pass
	void SetPemPass( const CS_STRING & s ) { m_sPemPass = s; }
	//! set to true if require a client certificate (deprecated @see SetRequireClientCertFlags)
	void SetRequiresClientCert( bool b ) { m_iRequireCertFlags = ( b ? SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0 ); }
	//! bitwise flags, 0 means don't require cert, SSL_VERIFY_PEER verifies peers, SSL_VERIFY_FAIL_IF_NO_PEER_CERT will cause the connection to fail if no cert 
	void SetRequireClientCertFlags( unsigned int iRequireCertFlags ) { m_iRequireCertFlags = iRequireCertFlags; }
#endif /* HAVE_LIBSSL */
private:
	u_short		m_iPort;
	CS_STRING	m_sSockName, m_sBindHost;
	bool		m_bIsSSL;
	int			m_iMaxConns;
	u_int		m_iTimeout;
	CSSockAddr::EAFRequire	m_iAFrequire;

#ifdef HAVE_LIBSSL
	CS_STRING	m_sPemLocation, m_sPemPass, m_sCipher;
	unsigned int		m_iRequireCertFlags;
#endif /* HAVE_LIBSSL */
};

#ifdef HAVE_LIBSSL
class CSSSListener : public CSListener
{
public:
	CSSSListener( u_short iPort, const CS_STRING & sBindHost = "" ) :
		CSListener( iPort, sBindHost )
	{
		SetIsSSL( true );
	}
};
#endif /* HAVE_LIBSSL */

/**
* @class TSocketManager
* @brief Best class to use to interact with the sockets
*
* handles SSL and NON Blocking IO
* Its a template class since Csock derives need to be new'd correctly
* Makes it easier to use overall
* Rather then use it directly, you'll probably get more use deriving from it
* Another thing to note, is that all sockets are deleted implicitly, so obviously you
* cant pass in Csock classes created on the stack. For those of you who don't
* know STL very well, the reason I did this is because whenever you add to certain stl containers
* (ie vector, or map), its completely rebuilt using the copy constructor on each element.
* That then means the constructor and destructor are called on every item in the container.
* Not only is this more overhead then just moving pointers around, its dangerous as if you have
* an object that is newed and deleted in the destructor the value of its pointer is copied in the
* default copy constructor. This means everyone has to know better and create a copy constructor,
* or I just make everyone new their object :)
*
* class CBlahSock : public TSocketManager<SomeSock>
*
* @author Jim Hull <imaginos@imaginos.net>
*/

template<class T>
class TSocketManager : protected CSocketManagerBase
{
public:
	TSocketManager() : CSocketManagerBase()
	{
		m_tCallTimeouts = ev_now(EV_DEFAULT_UC);

		m_prepare.data = this;
		ev_prepare_init(&m_prepare, Prepare);
		ev_prepare_start(EV_DEFAULT_UC_ &m_prepare);
	}

	virtual ~TSocketManager()
	{
		Cleanup();
		ev_prepare_stop(EV_DEFAULT_UC_ &m_prepare);
	}

	virtual void Cleanup()
	{
		while (!m_sSocks.empty()) {
			delete *m_sSocks.begin();
			m_sSocks.erase(m_sSocks.begin());
		}

		while (!m_sCrons.empty()) {
			delete *m_sCrons.begin();
			m_sCrons.erase(m_sCrons.begin());
		}
	}

	/**
	* Create a connection
	*
	* @param cCon the connection which should be established
	* @param pcSock the socket used for the connectiong, can be NULL
	* @return true on success
	*/
	bool Connect( const CSConnection & cCon, T * pcSock = NULL )
	{
		// create the new object
		if ( !pcSock )
			pcSock = new T( cCon.GetHostname(), cCon.GetPort(), cCon.GetTimeout() );
		else
		{
			pcSock->SetHostName( cCon.GetHostname() );
			pcSock->SetPort( cCon.GetPort() );
			pcSock->SetTimeout( cCon.GetTimeout() );
		}

		if( cCon.GetAFRequire() != CSSockAddr::RAF_ANY )
			pcSock->SetAFRequire( cCon.GetAFRequire() );

		// bind the vhost
		pcSock->SetBindHost( cCon.GetBindHost() );

#ifdef HAVE_LIBSSL
		pcSock->SetSSL( cCon.GetIsSSL() );
		if( cCon.GetIsSSL() )
		{
			if( !cCon.GetPemLocation().empty() )
			{
				pcSock->SetPemLocation( cCon.GetPemLocation() );
				pcSock->SetPemPass( cCon.GetPemPass() );
			}
			if( !cCon.GetCipher().empty() )
				pcSock->SetCipher( cCon.GetCipher() );
		}
#endif /* HAVE_LIBSSL */

		pcSock->SetType( T::OUTBOUND );

		pcSock->SetConState( T::CST_START );
		AddSock( pcSock, cCon.GetSockName() );
		return( true );
	}

	virtual bool Listen( const CSListener & cListen, T * pcSock = NULL, u_short *piRandPort = NULL )
	{
		if ( !pcSock )
			pcSock = new T();

		if( cListen.GetAFRequire() != CSSockAddr::RAF_ANY )
		{
			pcSock->SetAFRequire( cListen.GetAFRequire() );
#ifdef HAVE_IPV6
			if( cListen.GetAFRequire() == CSSockAddr::RAF_INET6 )
				pcSock->SetIPv6( true );
#endif /* HAVE_IPV6 */
		}
#ifdef HAVE_LIBSSL
		pcSock->SetSSL( cListen.GetIsSSL() );
		if( ( cListen.GetIsSSL() ) && ( !cListen.GetPemLocation().empty() ) )
		{
			pcSock->SetPemLocation( cListen.GetPemLocation() );
			pcSock->SetPemPass( cListen.GetPemPass() );
			pcSock->SetCipher( cListen.GetCipher() );
			pcSock->SetRequireClientCertFlags( cListen.GetRequireClientCertFlags() );
		}
#endif /* HAVE_LIBSSL */

		if( piRandPort )
			*piRandPort = 0;

		if ( pcSock->Listen( cListen.GetPort(), cListen.GetMaxConns(), cListen.GetBindHost(), cListen.GetTimeout() ) )
		{
			AddSock( pcSock, cListen.GetSockName() );
			if( ( piRandPort ) && ( cListen.GetPort() == 0 ) )
			{
				int iSock = pcSock->GetSock();

				if ( iSock < 0 )
				{
					CS_DEBUG( "Failed to attain a valid file descriptor" );
					pcSock->Close();
					return( false );
				}
				struct sockaddr_in mLocalAddr;
				socklen_t mLocalLen = sizeof( mLocalAddr );
				getsockname( iSock, (struct sockaddr *) &mLocalAddr, &mLocalLen );
				*piRandPort = ntohs( mLocalAddr.sin_port );
			}
			return( true );
		}

		CS_Delete( pcSock );
		return( false );
	}


	static void Prepare(EV_P_ ev_prepare *prep, int revents)
	{
		TSocketManager *p = (TSocketManager *) prep->data;
		p->Prepare();
	}

	void Prepare()
	{
		typename std::set<T *>::iterator it = m_sNeedAttentionSocks.begin();

		while (it != m_sNeedAttentionSocks.end())
		{
			T *pcSock = *it;

			// We don't need that iterator anymore, make it point to
			// the next item.
			it++;

			// close any socks that have requested it
			Csock::ECloseType eCloseType = pcSock->GetCloseType();
			if (eCloseType == T::CLT_NOW || eCloseType == T::CLT_DEREFERENCE ||
					(eCloseType == T::CLT_AFTERWRITE && pcSock->GetWriteBuffer().empty())) {
				// This will also remove it from m_vNeedAttentionSocks
				DelSockByAddr(pcSock);
				continue;
			}

			if (pcSock->GetConState() == T::CST_OK) {
				// We regularly call ReadPaused() on sockets
				// that have paused reading so that they can
				// un-pause if they want
				if (pcSock->IsReadPaused())
					pcSock->ReadPaused();
				else
					RemoveAttention(pcSock);
				continue;
			}

			if (pcSock->GetType() != T::OUTBOUND) {
				RemoveAttention(pcSock);
				continue;
			}

			if ( pcSock->GetConState() == T::CST_DNS )
			{
				if ( pcSock->DNSLookup( T::DNS_VHOST ) == ETIMEDOUT )
				{
					pcSock->SockError( EDOM );
					DelSockByAddr(pcSock);
					continue;
				}
			}

			if ( pcSock->GetConState() == T::CST_BINDVHOST )
			{
				if ( !pcSock->SetupVHost() )
				{
					pcSock->SockError( errno );
					DelSockByAddr(pcSock);
					continue;
				}
			}

			if ( pcSock->GetConState() == T::CST_DESTDNS )
			{
				if ( pcSock->DNSLookup( T::DNS_DEST ) == ETIMEDOUT )
				{
					pcSock->SockError( EADDRNOTAVAIL );
					DelSockByAddr(pcSock);
					continue;
				}
			}
			if ( pcSock->GetConState() == T::CST_CONNECT )
			{
				if ( !pcSock->Connect( pcSock->GetBindHost(), true ) )
				{
					if ( GetSockError() == ECONNREFUSED )
						pcSock->ConnectionRefused();
					else
						pcSock->SockError( GetSockError() );

					DelSockByAddr(pcSock);
					continue;
				}
			}
#ifdef HAVE_LIBSSL
			if( pcSock->GetConState() == T::CST_CONNECTSSL )
			{
				if ( pcSock->GetSSL() )
				{
					if ( !pcSock->ConnectSSL() )
					{
						if ( GetSockError() == ECONNREFUSED )
							pcSock->ConnectionRefused();
						else
							pcSock->SockError( GetSockError() == 0 ? ECONNABORTED : GetSockError() );

						DelSockByAddr(pcSock);
						continue;
					}
				}
			}
#endif /* HAVE_LIBSSL */
		}

		ev_tstamp iNow = ev_now(EV_DEFAULT_UC);
		ev_tstamp iDiff = iNow - m_tCallTimeouts;

		// Either a second passed or the clock went backwards
		if (iDiff >= 1 || iDiff < 0)
		{
			m_tCallTimeouts = iNow;

			for (const_iterator it2 = begin(); it2 != end(); it2++)
			{
				(*it2)->Cron();
			}

			// clean up the Cron handler here
			Cron();
		}
	}

	virtual void AddSock(Csock *pcSock, const CS_STRING & sSockName)
	{
		AddSock((T *) pcSock, sSockName);
	}

	/**
	* Make this method virtual, so you can override it when a socket is added.
	* Assuming you might want to do some extra stuff
	*/
	virtual void AddSock( T *pcSock, const CS_STRING & sSockName )
	{
		pcSock->SetSockName( sSockName );
		m_sSocks.insert(pcSock);
		pcSock->SetManager(this);
		AddAttentionSock((Csock *) pcSock);
	}

	virtual void AddAttentionSock(Csock *pcSock)
	{
		m_sNeedAttentionSocks.insert((T *) pcSock);
	}

	virtual void RemoveAttention(Csock *pcSock)
	{
		m_sNeedAttentionSocks.erase((T *) pcSock);
	}

	//! returns a pointer to the FIRST sock found by port or NULL on no match
	virtual T * FindSockByRemotePort( u_short iPort )
	{
		for (const_iterator it = begin(); it != end(); it++)
		{
			if ((*it)->GetRemotePort() == iPort)
				return *it;
		}

		return( NULL );
	}

	//! returns a pointer to the FIRST sock found by port or NULL on no match
	virtual T * FindSockByLocalPort( u_short iPort )
	{
		for (const_iterator it = begin(); it != end(); it++)
			if ((*it)->GetLocalPort() == iPort)
				return *it;

		return( NULL );
	}

	//! returns a pointer to the FIRST sock found by name or NULL on no match
	virtual T * FindSockByName( const CS_STRING & sName )
	{
		typename std::set<T *>::iterator it;
		typename std::set<T *>::iterator it_end = m_sSocks.end();
		for( it = m_sSocks.begin(); it != it_end; it++ )
			if ( (*it)->GetSockName() == sName )
				return( *it );

		return( NULL );
	}

	//! returns a pointer to the FIRST sock found by filedescriptor or NULL on no match
	virtual T * FindSockByFD( int iFD )
	{
		for (const_iterator it = begin(); it != end(); it++)
			if ((*it)->GetRSock() == iFD || (*it)->GetWSock() == iFD)
				return *it;

		return( NULL );
	}

	virtual std::set<T *> FindSocksByName( const CS_STRING & sName )
	{
		std::set<T *> vpSocks;

		for (const_iterator it = begin(); it != end(); it++)
			if ((*it)->GetSockName() == sName)
				vpSocks.insert(*it);

		return( vpSocks );
	}

	//! returns a set of pointers to socks with sHostname as being connected
	virtual std::set<T *> FindSocksByRemoteHost( const CS_STRING & sHostname )
	{
		std::set<T *> vpSocks;

		for (const_iterator it = begin(); it != end(); it++)
			if ((*it)->GetHostName() == sHostname)
				vpSocks.insert(*it);

		return( vpSocks );
	}

	//! add a cronjob at the manager level
	virtual void AddCron(CCron *pcCron)
	{
		m_sCrons.insert(pcCron);
	}

	/**
	 * @brief deletes a cron by name
	 * @param sName the name of the cron
	 * @param bDeleteAll delete all crons that match sName
	 * @param bCaseSensitive use strcmp or strcasecmp
	 */
	virtual void DelCron( const CS_STRING & sName, bool bDeleteAll = true, bool bCaseSensitive = true )
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

	//! delete cron by address
	virtual void DelCronByAddr( CCron *pcCron )
	{
		// First check if it's really in there, just because we can
		if (m_sCrons.find(pcCron) == m_sCrons.end())
			return;

		m_sCrons.erase(pcCron);
		CS_Delete(pcCron);
	}

	std::set<CCron *> & GetCrons() { return( m_sCrons ); }

	//! Delete a sock by addr
	//! the socket is deleted, the appropriate call backs are peformed
	//! and its instance is removed from the manager
	virtual void DelSockByAddr( T *pSock )
	{
		if (m_sSocks.find(pSock) == m_sSocks.end())
		{
			CS_DEBUG( "Invalid Sock removed! [" << pSock << "]" );
			return;
		}

		if( pSock->GetCloseType() != T::CLT_DEREFERENCE )
		{
			if ( pSock->IsConnected() )
				pSock->Disconnected(); // only call disconnected event if connected event was called (IE IsConnected was set)

			m_iBytesRead += pSock->GetBytesRead();
			m_iBytesWritten += pSock->GetBytesWritten();
		}

		T * pTmpSock = pSock;

		CS_Delete( pSock );

		// Do this after the socket was deleted, the destructor could
		// register the socket again (pTmpSock because CS_Delete eats babies)
		RemoveAttention(pTmpSock);
		m_sSocks.erase(pTmpSock);
	}


	/**
	 * @brief swaps out a sock with a copy of the original sock
	 * @param pNewSock the new sock to change out with. (this should be constructed by you with the default ctor)
	 * @param pOrigSock the address of the original socket
	 * @return true on success
	 */
	virtual bool SwapSockByAddr( T *pNewSock, T *pOrigSock )
	{
		if (m_sSocks.find(pOrigSock) == m_sSocks.end())
		{
			CS_DEBUG( "Invalid Sock Requested! [" << pOrigSock << "]" );
			return false;
		}

		pNewSock->Copy( *pOrigSock );
		pOrigSock->Dereference();

		m_sSocks.insert(pNewSock);
		// Both sockets are now in our socket set, the old one will be
		// cleaned up because of CLT_DEREFERENCE.

		return true;
	}

	//! Get the bytes read from all sockets current and past
	unsigned long long GetBytesRead() const
	{
		// Start with the total bytes read from destroyed sockets
		unsigned long long iRet = m_iBytesRead;

		// Add in the outstanding bytes read from active sockets
		for (const_iterator it = begin(); it != end(); it++)
			iRet += (*it)->GetBytesRead();

		return( iRet );
	}

	//! Get the bytes written to all sockets current and past
	unsigned long long GetBytesWritten() const
	{
		// Start with the total bytes written to destroyed sockets
		unsigned long long iRet = m_iBytesWritten;

		// Add in the outstanding bytes written to active sockets
		for (const_iterator it = begin(); it != end(); it++)
			iRet += (*it)->GetBytesWritten();

		return( iRet );
	}

	void Loop()
	{
		ev_loop(EV_DEFAULT_UC_ 0);
	}

	//! these crons get ran and checked in Loop()
	virtual void Cron()
	{
		std::set<CCron *>::iterator it = m_sCrons.begin();

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

	////////
	// Iterators

	typedef typename std::set<T *>::const_iterator const_iterator;
	const_iterator begin() const { return m_sSocks.begin(); }
	const_iterator end() const { return m_sSocks.end(); }
	size_t size() const { return m_sSocks.size(); }

	///////////
	// members
private:
	std::set<T *>			m_sSocks;
	std::set<CCron *>		m_sCrons;
	std::set<T *>			m_sNeedAttentionSocks;
	unsigned long long		m_iBytesRead;
	unsigned long long		m_iBytesWritten;
	ev_tstamp			m_tCallTimeouts;
	ev_prepare			m_prepare;
};

//! basic socket class
typedef TSocketManager<Csock> CSocketManager;

#ifndef _NO_CSOCKET_NS
}
#endif /* _NO_CSOCKET_NS */

#endif /* _HAS_CSOCKET_ */

