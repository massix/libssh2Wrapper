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
#include "Exception.h"
#include "UserInfo.h"

#include <iostream>

using namespace SSH2Wrapper;

using std::cout;
using std::endl;

int main ()
{
	try {
		Connection connection("hostname", 22, true);
//		connection.setCredentials("", "");
//		connection.setKeyPath("");

		UserInfo ui = connection.getUserInfo();

		cout 	<< "User infos:\n"
				<< "   login: " << ui.getUserName() << endl
				<< "    home: " << ui.getHomeDir() << endl
				<< "   shell: " << ui.getUserShell() << endl;

		connection.mkConnection();

		if (connection.isSessionValid())
			cout << "Connection OK" << endl;

		connection 	>> "whoami"
					>> "id"
					>> "echo 'test' > msg"
					>> "cat msg";

		string received_out = connection.getLastOutput();
		cout << "Received output: " << endl << received_out << endl;

	} catch (Exception & e) {
		cout << "Exception caught: " << e.what() << endl;
	}

	return 0;
}


