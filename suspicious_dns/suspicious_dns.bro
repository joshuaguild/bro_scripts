# raises notice if host attempts communications with multiple NXDOMAINs in short period of time
# Josh Guild: joshuaguild@gmail.com
# lemme know if you use it and how it goes :)

@load base/frameworks/sumstats

module Suspicious_DNS;

export {
    redef enum Notice::Type += {
    Multiple_NXDOMAINs,
    };
}

event DNS::log_dns(rec: DNS::Info)
    {
    # define whitelist in site.bro local_nets variable
    local whitelist = Site::local_nets;
    if ( rec?$rcode && rec$rcode == 3 && rec$id$resp_h !in whitelist )
    SumStats::observe("dns.NXDOMAIN", SumStats::Key($host=rec$id$orig_h), SumStats::Observation($num=1));
    }

event bro_init()
    {
    local r1 = SumStats::Reducer($stream="dns.NXDOMAIN", $apply=set(SumStats::SUM));

    SumStats::create([$name = "NXDOMAINs.seen",
                      $epoch = 0.25sec,
                      $reducers = set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["dns.NXDOMAIN"]$sum;
                          },
                      $threshold=5.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local r = result["dns.NXDOMAIN"];
                          local dur = duration_to_mins_secs(r$end-r$begin);
                          NOTICE([$note=Multiple_NXDOMAINs,
                                  $msg=fmt("%s made at least %.0f NXDOMAIN requests in %s!", key$host, r$sum, dur),
                                  $src=key$host]);
                    }]);
    }
