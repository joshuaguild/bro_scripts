# Suspicious DNS
**suspicious_dns.bro** - This script looks for failed domain lookups (NXDOMAIN) as malware goes through its C2 and will a notice in the notice.log with the format "<host> made at least <number> NXDOMAIN requests in <time>" if the threshold is reached. You can tweak the timeframe and number of NXDOMAINs required for the threshold using the $epoch and $threshold values (respectively). It whitelists Site::local_nets as defined in site.bro so internal DNS servers don't explode your notice.log.

QA'd with a few pcaps using the tag:suspicious-dns on Virustotal as well as some private traffic. Everything went well but no warranty is implied :D
