
# RDP Keyboard Layout                                                                                                 
Checks keyboard_layout in rdp.log against a whitelist of keyboard language sets (populated from your choice in this list - https://www.bro.org/sphinx/scripts/base/protocols/rdp/consts.bro.html#id-RDP::languages) and plops a notice the weird.log.

TODO: Try to pull in the RDP::languages set to populate the alert with the string instead of just using the count.

