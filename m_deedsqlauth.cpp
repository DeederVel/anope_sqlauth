/*
m_deedsqlauth.cpp
2016-2017 Mattia "DeederVel" Dui
Module for Anope IRC Services v2.0.5, lets users authenticate with
credentials stored in a pre-existing SQL server instead of the internal
Anope database.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <iostream>
#include <stdio.h>
#include <string>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "module.h"
#include "modules/sql.h"

/* 
    THIS MODULE USES https://github.com/rg3/bcrypt FOR
    THE ENCRYPTION AND CHECK OF THE PASSWORDS.
    PLEASE DOWNLOAD THE LIBRARY FIRST AND CHANGE THESE
    INCLUDEs DIRECTORIES ACCORDINGLY
*/
#include "/opt/bcrypt/bcrypt.c"
#include "/opt/bcrypt/crypt_blowfish/crypt_blowfish.c"
#include "/opt/bcrypt/crypt_blowfish/crypt_gensalt.c"
#include "/opt/bcrypt/crypt_blowfish/wrapper.c"

static Module *me;

class SQLAuthenticationResult : public SQL::Interface
{
	Reference<User> user;
	IdentifyRequest *req;
	Anope::string currPass;
	
    //Casting function to get the std::string out of the Anope one.
	std::string ritornaStr(Anope::string inp) {
		char* inputc = new char[inp.length() + 1];
		strcpy(inputc, inp.c_str());
		std::string retstr(inputc);
		return retstr;
	}

 public:
	SQLAuthenticationResult(User *u, Anope::string cp, IdentifyRequest *r) : SQL::Interface(me), user(u), req(r)
	{
		req->Hold(me);
		this->currPass = cp;
	}

	~SQLAuthenticationResult()
	{
		req->Release(me);
	}
	
	void find_and_replace(std::string& source, std::string const& find, std::string const& replace)
	{
		for(std::string::size_type i = 0; (i = source.find(find, i)) != std::string::npos;)
		{
			source.replace(i, find.length(), replace);
			i += replace.length();
		}
	}
	std::string trim(const std::string& str)
	{
		size_t first = str.find_first_not_of(' ');
		if (std::string::npos == first)
		{
			return str;
		}
		size_t last = str.find_last_not_of(' ');
		return str.substr(first, (last - first + 1));
	}

	void OnResult(const SQL::Result &r) anope_override
	{
		if (r.Rows() == 0)
		{
			Log(LOG_COMMAND) << "[SQLAUTH]: User record @" << req->GetAccount() << "@ NOT found";
			delete this;
			return;
		}

		Log(LOG_COMMAND) << "[SQLAUTH]: User record @" << req->GetAccount() << "@ found";
		Log(LOG_COMMAND) << "[SQLAUTH]: Auth for user @" << req->GetAccount() << "@ processing...";

		Anope::string hash;
		Anope::string email;
		
		try
		{
			hash = r.Get(0, "password");
			email = r.Get(1, "email");
		}
		catch (const SQL::Exception &) { }		
		
		std::string passS = trim(this->currPass.str());
		std::string hashS = hash.str();
		int res;
		res = bcrypt_checkpw(passS.c_str(), hashS.c_str());
		if (res == -1) {
			Log(LOG_COMMAND) << "[SQLAUTH]: ERROR: hash NOT EQUAL pass";
		}
		
		if (res == 0) {
			Log(LOG_COMMAND) << "[SQLAUTH]: User @" << req->GetAccount() << "@ LOGGED IN";
			
			NickAlias *na = NickAlias::Find(req->GetAccount());
			BotInfo *NickServ = Config->GetClient("NickServ");
			if (na == NULL)
			{
				na = new NickAlias(req->GetAccount(), new NickCore(req->GetAccount()));
				FOREACH_MOD(OnNickRegister, (user, na, ""));
				if (user && NickServ)
					user->SendMessage(NickServ, _("Your account \002%s\002 has been confirmed."), na->nick.c_str());
			}

			if (!email.empty() && email != na->nc->email)
			{
				na->nc->email = email;
				if (user && NickServ)
					user->SendMessage(NickServ, _("E-mail set to \002%s\002."), email.c_str());
			}
			 
			req->Success(me);
		} else {
			Log(LOG_COMMAND) << "[SQLAUTH] Wrong pass/User not registered";
			delete this;
			return;
		}		
		delete this;
	}

	void OnError(const SQL::Result &r) anope_override
	{
		Log(this->owner) << "[SQLAUTH]: Error when executing query" << r.GetQuery().query << ": " << r.GetError();
		delete this;
	}
};

class ModuleSQLAuthentication : public Module
{
	Anope::string engine;
	Anope::string query;
	Anope::string disable_reason, disable_email_reason;

	ServiceReference<SQL::Provider> SQL;

 public:
	ModuleSQLAuthentication(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, EXTRA | VENDOR)
	{
		me = this;

	}

	void OnReload(Configuration::Conf *conf) anope_override
	{
		Configuration::Block *config = conf->GetModule(this);
		this->engine = config->Get<const Anope::string>("engine");
		this->query =  config->Get<const Anope::string>("query");
		this->disable_reason = config->Get<const Anope::string>("disable_reason");
		this->disable_email_reason = config->Get<Anope::string>("disable_email_reason");

		this->SQL = ServiceReference<SQL::Provider>("SQL::Provider", this->engine);
	}

	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) anope_override
	{
		if (!this->disable_reason.empty() && (command->name == "nickserv/register" || command->name == "nickserv/group"))
		{
			source.Reply(this->disable_reason);
			return EVENT_STOP;
		}

		if (!this->disable_email_reason.empty() && command->name == "nickserv/set/email")
		{
			source.Reply(this->disable_email_reason);
			return EVENT_STOP;
		}

		return EVENT_CONTINUE;
	}

	void OnCheckAuthentication(User *u, IdentifyRequest *req) anope_override
	{
		if (!this->SQL)
		{
			Log(this) << "Unable to find SQL engine";
			return;
		}

		SQL::Query q(this->query);
		q.SetValue("a", req->GetAccount());
		q.SetValue("p", req->GetPassword());
		if (u)
		{
			q.SetValue("n", u->nick);
			q.SetValue("i", u->ip.addr());
		}
		else
		{ 
			q.SetValue("n", "");
			q.SetValue("i", "");
		}


		this->SQL->Run(new SQLAuthenticationResult(u, req->GetPassword(), req), q);
	}
};

MODULE_INIT(ModuleSQLAuthentication)
