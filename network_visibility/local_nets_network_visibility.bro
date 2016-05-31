# tracks network visibility and logs using Site::local_nets                                                           # Josh Guild: joshuaguild@gmail.com
# lemme know if you use it and how it goes :)

module Visibility;

# Uses networks defined in Site::local_nets
global net_conn_nets: set[subnet];

export {
        # Log ID
        redef enum Log::ID += { LOG };
        
        # define record types for log - this includes seen_host and subnet_CIDR
        type Info: record {
                seen_host:      addr    &log;
                subnet_CIDR:    subnet  &log;
        };
}

event bro_init()
{
	Log::create_stream(Visibility::LOG, [$columns=Info, $path="visibility"]);
	net_conn_nets = Site::local_nets;
}

event new_connection(c: connection)
{
        # define new_host var for incoming connections in conn.log
        local new_host = c$id$orig_h;
        
        # check for new_host in defined networks in Site::local_nets
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


