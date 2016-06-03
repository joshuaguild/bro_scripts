# Logs rerdirct messages in HTTP traffic
# Josh Guild: joshuaguild@gmail.com
#
# TODO: This is a little hacky, I'd like to just add a column to the http.log

@load base/protocols/conn
@load base/protocols/http

module Redirect;

global redirect_status_codes: set[count] = {
	301,
	302,
	303,
	307,
	308
};

export {
	redef enum Log::ID += { LOG };
        
        type Info: record {
        	ts:             time      &log;
		uid:            string    &log;
		id:             conn_id   &log;
		host:           string    &log &optional;
		uri:            string    &log &optional;
		referrer:       string    &log &optional;
		status_code:    count     &log &optional;
		status_msg:     string    &log &optional;
		redirected_to:  string    &log;
        };
}

event bro_init()
{
Log::create_stream(Redirect::LOG, [$columns=Info, $path="redirect"]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (c$http?$status_code == T)
	{
		local code = c$http$status_code;
	
		if(code in redirect_status_codes && name == "LOCATION")
			{
			Log::write(Redirect::LOG, [$ts=c$http$ts, $uid=c$uid, $id=c$id, $host=c$http$host, $uri=c$http$uri, $referrer=c$http$referrer, $status_code=c$http$status_code, $status_msg=c$http$status_msg, $redirected_to=value]);
			}
	}
}
