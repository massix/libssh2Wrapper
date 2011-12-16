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

#ifndef USERINFO_H_
#define USERINFO_H_

#include <string>
#include "Exception.h"

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

using std::string;
using SSH2Wrapper::Exception;

typedef unsigned int uint;

namespace SSH2Wrapper {

class UserInfo {
public:
	UserInfo () throw (Exception);
	UserInfo (const string & login) throw (Exception);

	virtual ~UserInfo();
    const string & getHomeDir() const;
    uint getUserGid() const;
    const string & getUserName() const;
    const string & getUserShell() const;
    uint getUserUid() const;

private:
	string	userName;
	string	homeDir;
	uint	userUid;
	uint	userGid;
	string	userShell;

	void retrieveAllInformations ();

	struct passwd * userInfos;
};

} /* namespace SSH2Wrapper */
#endif /* USERINFO_H_ */
