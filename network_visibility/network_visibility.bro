module Visibility;

# add subnet CIDRs you'd like to check for here
global net_conn_nets = set(192.168.0.0/16,10.0.0.0/8,172.16.0.0/12);

export {
        # Log ID
        redef enum Log::ID += { LOG };
	
	# define record types for log - this includes seen_host and subnet_CIDR
        type Info: record {
                seen_host:   	addr    &log;
                subnet_CIDR:	subnet  &log;
        };
}

event bro_init()
{
Log::create_stream(Visibility::LOG, [$columns=Info, $path="visibility"]);
}

event new_connection(c: connection)
{
	# define new_host var for incoming connections in conn.log
    	local new_host = c$id$orig_h;
	
	# check for new_host in defined subnets
	for(n in net_conn_nets)
    {
        if(new_host in n)
        {
		Log::write( Visibility::LOG, [$seen_host=new_host, $subnet_CIDR=n]);
		
		# delete subnet from list if host is included
            	delete net_conn_nets[n];
        }
    }
}
