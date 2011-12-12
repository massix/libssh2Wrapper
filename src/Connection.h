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

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <libssh2.h>
#include <string>
#include <netdb.h>

#include "Exception.h"

using std::string;
using SSH2Wrapper::Exception;

namespace SSH2Wrapper {

class Connection {

public:
	Connection (bool useKey) throw (Exception);
	Connection (const string & hostName, uint port) throw (Exception);
	Connection (const string & hostName, uint port, bool useKey) throw (Exception);

	virtual ~Connection ();

	void			mkConnection() throw (Exception);
	const string &	executeCmd (const string & cmd) throw (Exception);
	const string &	operator>> (const string & cmd) throw (Exception);
	const string &	operator() (const string & cmd) throw (Exception);


    /* Getters and setters */
    uint getPort() const;
    bool isUsingKey() const;
    bool isSessionValid() const;
    string getHostName() const;
    string getLastError() const;
    string getLastExecutedCmd() const;
    void setHostName(const string & hostName);
    void setPort(uint port);
    void setUsingKey(bool usingKey);
    void setCredentials (const string & userName, const string & password);
    void setKeyPath (const string & path);

private:
	string				lastError;
	string				lastExecutedCmd;

	LIBSSH2_SESSION * 	session;

	string				hostName;
	uint				port;
	bool				usingKey;
	bool				sessionValid;

	string				userName;
	string				password;
	string				keyPath;

	uint				hSocket;
};

} /* namespace SSH2Wrapper */
#endif /* CONNECTION_H_ */
