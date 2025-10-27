# I want to go over subnets given here
# for the first 10 new connections i get - will be checked by a global counting variable
# I'll print the src ip, src port, dst ip, dst port. connection id - uid, time of start connection
#The name of the fields are:

# time of connection = ts
# connection id - uid
# src ip - id.orig_h
# src port - id.orig_p
# dst ip - id.resp_h
# dst port - id.resp_p
# protocol - proto, apllication level protocol - service


# After the 10th connection - I'll want to just print the connection object
#In addition, I'll hold a set of ip addresses - type addr
# For each address in a connection - src address and destination address i'll check if it's already inside the set
# If yes: i'll move on
# If not: i'll add to set, than check if it is a local or external ip address



#What do I need to use:

#1. I need a record - it'll hold all fields i want to print for the first 10 connections - sort of a struct
#    so it will be easier to work with
#2. I need a set of type addr - It'll hold all ip addresses i saw in my connections - basically the entire pcap file
 #   Than we can check that way if the IP address is unique or not - and print whther it is local or not using a helper function
#3. I want a set of type subnet - it will be all local subnets and a parameter to the helper functions that will check
 #    whether the addr is local or not
#4.Helper function - recive ip address and list of subnets (default the set from (3)) and return true / false
 #   whether the addr is part of any of the subnets
#5. event connection_established - will pop up every time a tcp handshake is completed or when new udp packet is sent - exactly
 #   the event handler we need here
#6. Global variables:
  #  a. num_of_connections - will count basically the number of times we enter the event
   #     When the value is 10 - we can stop printing details about connections




######################################################################################################################
#loading the framework to use the connections events
@load base/protocols/conn

module ListingConnections;


export {
#This is the struct that defines the fields i want to print for first 10 connections
type PacketHeader : record {
    src_ip : addr;
    src_port : port;
    dst_ip : addr;
    dst_port : port;
    transport_protocol : string;
    curr_time : time;
    id : string;
};

# This is the set of subnets that define whether the address is local or not
const local_subnets: set[subnet] = {
    192.168.1.0/24,
    192.68.2.0/24,
    172.16.0.0/20,
    172.16.16.0/20,
    172.16.32.0/20,
    172.16.48.0/20
};
}


global addresses: set[addr] = {
};

global num_of_connections : count = 0;


function proto_to_string(p: count): string
    {
    if ( p == 6 )  return "tcp";
    if ( p == 17 ) return "udp";
    if ( p == 1 )  return "icmp";
    return fmt("unknown(%d)", p);
    }
# This will be the helper function that receives an ip addr and vector of subnets and return true whether that ip 
# addr is in one of the subnets
function ip_in_subnet(ip : addr, subnets : set[subnet] &default = ListingConnections::local_subnets) : bool
{
    for (s in subnets)
    {
        if (ip in s)
        {
            return T;
        }
    }
    return F;
}

#This will be the main event - function actually running
# It will be triggered every time a tcp handshake is established / upon the first communication of udp connection
event connection_established(c:connection)
{
    
    local header : PacketHeader = PacketHeader($src_ip = c$id$orig_h, $src_port = c$id$orig_p,
    $dst_ip = c$id$resp_h, $dst_port = c$id$resp_p, $transport_protocol = proto_to_string(c$id$proto), 
    $curr_time = c$start_time, $id = c$uid);

    if(num_of_connections < 10)
    {
        # This is a great use of records - this way i can just print the entire object in a human readable form like
        # data class in kotlin
        print header;
    }
    num_of_connections += 1;
    
    

}
event zeek_init()
{
    print fmt("Starting to monitor connections");
}


event zeek_done()
{
    print "Done Processing";
}