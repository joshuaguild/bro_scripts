# Network Visibilty
**network_visibility.bro** - This script can be run to verify visibility into your network. You can add the subnets you're looking for in the net_conn_nets variable. From there, the script will output the first host it sees in the conn.log for that given subnet, write it to the visibility.log, and delete it from the set. Ideally, if you have 10 subnets you're expecting to see, you *should* have 10 lines in your visibility.log.

**local_nets_network_visibility.bro** - Second flavor uses the networks defined in Site::local_nets as the subnets to look for so you can keep a clean running list (thanks to Seth for the assist on this).
