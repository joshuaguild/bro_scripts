# checks keyboard_layout for RDP sessions                                                                             
# Josh Guild: joshuaguild@gmail.com
# lemme know if you use it and how it goes :)

@load base/protocols/rdp
@load base/frameworks/notice/weird.bro 

module RDP_layout;

# Set keyboard whitelist here (defaulting to English)
global layout_wl: set[count] = {
	1033, #English - United States
	6153, #English - Ireland
	2057, #English - UK
	4105, #English - Canada
	3081, #English - Australia
	
};

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData)
{
   
   local kl = data$keyboard_layout;
   
    if (kl !in layout_wl)
        {
        NOTICE([$note=Weird::Activity,
        		$conn=c,
                $msg=fmt("Non-English keyboard layout seen in rdp.log - language set to %s.", kl)]);
        }
}
