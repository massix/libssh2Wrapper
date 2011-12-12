/*
 * Copyright (C) 2011 Massimo Gengarelli <massimo.gengarelli@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "Connection.h"

#ifdef DEBUG
#include <iostream>

using std::cout;
using std::endl;
#endif

namespace SSH2Wrapper {

Connection::~Connection()
{
	if (isSessionValid()) {
		libssh2_session_disconnect(session, "SSH2Wrapper disconnected.");
		libssh2_session_free(session);
	}

	close (hSocket);
}

string Connection::getHostName() const
{
	return hostName;
}

string Connection::getLastError() const
{
	return lastError;
}

string Connection::getLastExecutedCmd() const
{
	return lastExecutedCmd;
}

uint Connection::getPort() const
{
	return port;
}

bool Connection::isUsingKey() const
{
	return usingKey;
}

bool Connection::isSessionValid() const
{
	return sessionValid;
}

void Connection::setHostName(const string & hostName)
{
	this->hostName = hostName;
}

void Connection::setPort(uint port)
{
	this->port = port;
}

Connection::Connection(bool useKey) throw (Exception) :
	hostName("localhost"), port(22), usingKey(useKey), sessionValid(false)
{
#ifdef DEBUG
	cout 	<< "Object initialized with\n"
			<< "    hostname -> " << this->hostName << endl
			<< "    port     -> " << this->port << endl
			<< "    usingKey -> " << this->usingKey << endl;
#endif
}

Connection::Connection(const string & hostName, uint port) throw (Exception) :
	hostName(hostName), port(port), usingKey(false), sessionValid(false)
{
#ifdef DEBUG
	cout 	<< "Object initialized with\n"
			<< "    hostname -> " << this->hostName << endl
			<< "    port     -> " << this->port << endl
			<< "    usingKey -> " << this->usingKey << endl;
#endif
}

Connection::Connection(const string & hostName, uint port, bool useKey) throw (Exception) :
	hostName(hostName), port(port), usingKey(useKey), sessionValid(false)
{
#ifdef DEBUG
	cout 	<< "Object initialized with\n"
			<< "    hostname -> " << this->hostName << endl
			<< "    port     -> " << this->port << endl
			<< "    usingKey -> " << this->usingKey << endl;
#endif
}

void Connection::mkConnection() throw (Exception)
{
	hSocket = -1;
	struct hostent * he = gethostbyname(hostName.c_str());

	if (!he)
		throw Exception ("Hostname lookup failed :(");

	struct sockaddr_in s;
	s.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	s.sin_family = he->h_addrtype;
	s.sin_port = htons (this->port);

	hSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket < 0)
		throw Exception ("Failed to create socket.");

	if (connect(hSocket, (struct sockaddr *) &s, sizeof (struct sockaddr_in)) < 0)
		throw Exception ("Failed to connect to remote host.");

	session = libssh2_session_init();

	if (libssh2_session_startup(session, hSocket) != 0)
		throw Exception ("Couldn't startup libssh2 :-(");

	if (usingKey) {
		string privateKey = keyPath;
		privateKey.append("/id_rsa");

		string publicKey = keyPath;
		publicKey.append("/id_rsa.pub");
#ifdef DEBUG
		cout 	<< "    authenticating using AUTHKEY\n"
				<< "    public key:  " << publicKey << endl
				<< "    private key: " << privateKey << endl;
#endif

		if (libssh2_userauth_publickey_fromfile(session, userName.c_str(), publicKey.c_str(), privateKey.c_str(), password.c_str()) != 0)
			throw Exception ("Couldn't authenticate using keypair provided.");
	}

	else {
#ifdef DEBUG
		cout << "    authenticating using USERNAME AND PASSWORD" << endl;
#endif
		if (libssh2_userauth_password(session, userName.c_str(), password.c_str()) != 0)
			throw Exception ("Couldn't authenticate using username and password provided.");
	}

	sessionValid = true;
}

const string & Connection::executeCmd(const string & cmd) throw (Exception)
{
	if (!isSessionValid())
		throw Exception ("How can you send commands if you don't connect?");

	LIBSSH2_CHANNEL * channel = libssh2_channel_open_session(session);

	if (channel == NULL)
		throw Exception ("Couldn't open a communication channel.");

	if (libssh2_channel_exec(channel, cmd.c_str()) == -1)
		throw Exception ("Couldn't exec the remote command.");

	lastExecutedCmd = cmd;

	libssh2_channel_close(channel);
	libssh2_channel_free(channel);

	return lastExecutedCmd;
}

const string & Connection::operator >>(const string & cmd) throw (Exception)
{
	return executeCmd(cmd);
}

const string & Connection::operator() (const string & cmd) throw (Exception)
{
	return executeCmd(cmd);
}

void Connection::setUsingKey(bool usingKey)
{
	this->usingKey = usingKey;
}

void Connection::setCredentials(const string & userName, const string & password)
{
	this->userName = userName;
	this->password = password;
}

void Connection::setKeyPath(const string & path)
{
	this->keyPath = path;
}

} /* namespace SSH2Wrapper */
