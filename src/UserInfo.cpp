/*
 * UserInfo.cpp
 *
 *  Created on: Dec 16, 2011
 *      Author: massi
 */

#include "UserInfo.h"

namespace SSH2Wrapper {



UserInfo::UserInfo() throw (Exception)
{
	userInfos = getpwnam(getlogin());
	if (!userInfos)
		throw Exception ("No informations retrieved.");

	retrieveAllInformations();
}


UserInfo::UserInfo(const string & login) throw (Exception)
{
	userInfos = getpwnam(login.c_str());
	if (!userInfos)
		throw Exception ("No informations retrieved.");

	retrieveAllInformations();
}

void UserInfo::retrieveAllInformations ()
{
	userName = string(userInfos->pw_name);
	homeDir = string(userInfos->pw_dir);
	userShell = string(userInfos->pw_shell);

	userUid = (uint) userInfos->pw_uid;
	userGid = (uint) userInfos->pw_gid;
}

UserInfo::~UserInfo()
{
}

const string & UserInfo::getHomeDir() const
{
    return homeDir;
}

uint UserInfo::getUserGid() const
{
    return userGid;
}

const string & UserInfo::getUserName() const
{
    return userName;
}

const string & UserInfo::getUserShell() const
{
    return userShell;
}

uint UserInfo::getUserUid() const
{
    return userUid;
}



} /* namespace SSH2Wrapper */
