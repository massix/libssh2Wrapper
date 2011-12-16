/*
 * UserInfo.h
 *
 *  Created on: Dec 16, 2011
 *      Author: massi
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
