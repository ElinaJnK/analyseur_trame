import java.util.*;
import java.util.concurrent.TimeUnit ;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;


public class Dhcp{
    private String info;
    //Message Type
    private String message_type;
    //Hardware Length
    private int hard_l;
    //Hops
    private int hops;
    //Transaction ID
    private String trans_id;
    //Seconds elapsed
    private int sec_elapsed;
    //Client IP address
    private String c_ip;
    //Your ip Adress
    private String y_ip;
    //Next server IP address
    private String next_ip;
    //Relay agent IP adress 
    private String relay_agent_ip;
    //Client mac adress
    private String c_mac;
    //Server Host Name;
    private StringBuilder server_hname;
    //Boot file Name;
    private StringBuilder bf_name;
    //Boot file
    private String bootp_f;
    //Options
    private StringBuilder opt;
    //Trame
    private List<String> trame;
    //Permet de verifier si la trame est valide 
    private boolean trameValide;
    //protocole IP encapsulant
    private Ip ip;
    //Taille de l'encapsulation
    private int encap_l;
    //Donne le chemin pour ecrire dans un fichier
    private Path path;
    //protcole UDP encapsulant
    private Udp udp;

    public Dhcp(List<String> tr, Ip ip, Udp udp, Path path){
        trame = tr;
        trameValide = true;
        this.ip = ip;
        this.path = path;
        this.udp = udp;
        int encap_l = 13 + ip.getHl()*4 + 8;
        message_type = trame.get(encap_l+1);
        hard_l = hexToDecimal(trame.get(encap_l + 3));
        hops = hexToDecimal(trame.get(encap_l + 4));
        trans_id = "0x" + trame.get(encap_l + 5) + trame.get(encap_l + 6) + trame.get(encap_l + 7) + trame.get(encap_l + 8);
        sec_elapsed = hexToDecimal(trame.get(encap_l + 9)+trame.get(encap_l + 10));
        bootp_f = trame.get(encap_l + 11) + trame.get(encap_l + 12);
        c_ip = ipBuilder(trame.get(encap_l + 13), trame.get(encap_l + 14), trame.get(encap_l + 15), trame.get(encap_l + 16));
        y_ip = ipBuilder(trame.get(encap_l + 17), trame.get(encap_l + 18), trame.get(encap_l + 19), trame.get(encap_l + 20));
        next_ip = ipBuilder(trame.get(encap_l + 21), trame.get(encap_l + 22), trame.get(encap_l + 23), trame.get(encap_l + 24));
        relay_agent_ip = ipBuilder(trame.get(encap_l + 25), trame.get(encap_l + 26), trame.get(encap_l + 27), trame.get(encap_l + 28));
        c_mac = trame.get(encap_l + 29)+":"+trame.get(encap_l + 30)+":"+trame.get(encap_l + 31)+":"+trame.get(encap_l + 32)+":"+trame.get(encap_l + 33)+":"+trame.get(encap_l + 34);
        server_hname = new StringBuilder();
        for (int i = 45 + encap_l; i < encap_l + 64 + 45; i++){
            server_hname.append(trame.get(i));
        }
        bf_name = new StringBuilder();
        for (int i = 45 + encap_l + 64; i < encap_l + 64 + 45 + 128; i++){
            bf_name.append(trame.get(i));
        }
        opt = new StringBuilder();
        List<String> temp;
        //sous la forme: encapsulation + file + sname + chadress + magic cookie
        for (int i = encap_l + 128 + 64 + 16 + 4 + 29; i < trame.size()-1 ; i++){
            int l = hexToDecimal(trame.get(i+1));
            if (l > 0){
                temp = new ArrayList<>();
                temp.add(trame.get(i));
                for (int j = 0; j <= l; j++){
                    temp.add(trame.get(i+1+j));
                }
                try{
                    opt.append(optionSolver(temp));
                }catch(Exception e){
                    trameValide = false;
                }

            }
            if (trame.get(i).contains("ff")){
                temp = new ArrayList<>();
                temp.add(trame.get(i));
                try{
                    opt.append(optionSolver(temp));
                }catch(Exception e){
                    trameValide = false;
                }
                opt.append("\tPadding: ");
                for (int j = i+1; j < trame.size(); j++){
                    opt.append("00");
                }
                opt.append("\n");
            }
            i += l + 1;
        }
    }

    public int hexToDecimal(String hex){
        /**Fonction qui permet de convertir un hexadecimal en int décimal**/
        return Integer.parseInt(hex,16);
    }

    public String ipBuilder(String i1, String i2, String i3, String i4){
        /**Fonction qui construit une chaîne ip**/
        return hexToDecimal(i1)+"."+hexToDecimal(i2)+"."+hexToDecimal(i3)+"."+hexToDecimal(i4);
    }

    public String hexTotext(String hex) {
        /**Transforme des caractère héxadécimal en caractères ASCII**/
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i+=2) {
            String str = hex.substring(i, i+2);
            output.append((char)Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    public String timeSolver(int ttl){
        /**Fonction qui permet de donner le temps**/
        StringJoiner sj = new StringJoiner(", ", " (", ")");
        int jours, heures, minutes;
        if (ttl/86400 >= 1) {
            jours = ttl/86400;
            ttl=  ttl - 86400*jours;
            sj.add(jours + " days");
        }	
        if (ttl/3600 >= 1) {
            heures = ttl/3600;
            ttl=  ttl - 3600*heures;
            sj.add(heures + "  hours");
        }
        if (ttl/60>= 1) {
            minutes = ttl/60;
            ttl=  ttl - 60*minutes;
            sj.add(minutes + "  minutes");
        }
        if (ttl != 0) sj.add(ttl + " seconds");
        return sj.toString();
    }

    public String optionSolver(List<String> option) throws Exception{
        /**Fonction qui permet de gérer les différentes options DHCP**/
        int len = 0;
        if (option.size() > 1){
            len = hexToDecimal(option.get(1));
        }
        String ip;
        StringBuilder o = new StringBuilder();
        StringBuilder s = new StringBuilder();
        switch(option.get(0)){
            case "00":
                o.append("\tOption: (0) Pad option\n\t\tPad Option: 0\n");
                break;
            case "ff":
                o.append("\tOption: (255) End\n\t\tOption End: 255\n");
                break;
            case "01":
                String ip3 = ipBuilder(option.get(2), option.get(3), option.get(4), option.get(5));
                o.append("\tOption: (1) Subnet Mask ("+ ip3 +")\n\t\tLength: 4\n\t\tSubnet Mask: "+ ip3 +"\n");
                break;
            case "03":
                o.append("\tOption: (3) Router\n\t\tLength: "+len+"\n");
                for (int i = 0 ; i < len; i += 4){
                    ip = ipBuilder(option.get(i+2), option.get(i+3), option.get(i+4), option.get(i+5));
                    o.append("\t\tRouteur: "+ip+"\n");
                }
                break;
            case "06":
                o.append("\tOption: (6) Domain Name Server\n\t\tLength: "+len+"\n");
                for (int i = 0 ; i < len; i += 4){
                    ip = ipBuilder(option.get(i+2), option.get(i+3), option.get(i+4), option.get(i+5));
                    o.append("\t\tDomain Name Server: "+ip+"\n");
                }
                break;
            case "09":
                o.append("\tOption: (9) LPR Server Option\n\t\tLength: "+len+"\n");
                for (int i = 0 ; i < len; i += 4){
                    ip = ipBuilder(option.get(i+2), option.get(i+3), option.get(i+4), option.get(i+5));
                    o.append("\t\tLPR Server Option: "+ip+"\n");
                }
                break;
            case "0c":
                for (int i = 0; i < len; i++){
                    s.append(hexTotext(option.get(i+2)));
                }
                o.append("\tOption: (12) Host Name\n\t\tLength: "+len+"\n\t\tHost Name: "+s.toString()+"\n");
                break;
            case "0f":
                ip = ipBuilder(option.get(2), option.get(3), option.get(4), option.get(5));
                o.append("\tOption: (15) Domain Name Option (+"+ ip +")\n\t\tLength: 4\n\t\tDomain Name Option: "+ ip +"\n");
                break;
            case "32":
                String ip1 = ipBuilder(option.get(2), option.get(3), option.get(4), option.get(5));
                o.append("\tOption: (50) Requested IP Adress ("+ ip1 +")\n\t\tLength: 4\n\t\tRequested IP Adress: "+ip1+"\n");
                break;
            case "33":
                int time = hexToDecimal(option.get(2)+ option.get(3)+option.get(4)+option.get(5));
                o.append("\tOption: (51) IP Address Lease Time\n\t\tLength: 4\n\t\tIP Adress Lease Time: ("+ time +"s) "+timeSolver(time)+"\n");
                break;
            case "34":
                String f = "";
                if (option.get(2) == "01"){
                    f = "Boot file name";
                }
                if (option.get(2) == "02"){
                    f = "Server Name";
                }else{
                    throw new Exception("Problème dans l'overload");
                }
                o.append("\tOption: (52) Option Overload\n\t\tLength: 1\n\t\tOption Overload: "+ f +"\n");
                break;
            case "35":
                String m = DHCPMessageType(option.get(2));
                o.append("\tOption: (53) DHCP Message Type("+ m +")\n\t\tLength: 1\n\t\tDHCP: "+ m +"\n");
                info = m;
                break;
            case "36":
                String ip2 = ipBuilder(option.get(2), option.get(3), option.get(4), option.get(5));
                o.append("\tOption: (54) Server Identifier ("+ ip2 +")\n\t\tLength: 4\n\t\tDHCP Server Identifier: "+ip2+"\n");
                break;
            case "37":
                o.append("\tOption: (55) Parameter Request List\n\t\tLength: "+ len +"\n");
                for (int i = 0; i < len; i++){
                    s.append("\t\tParameter Request List: "+ParameterRequestListSolver(option.get(i+2))+"\n");
                }
                o.append(s.toString());
                break;
            case "38":
                for (int i = 0; i < len; i++){
                    s.append(hexTotext(option.get(i+2)));
                }
                o.append("\tOption: (56) DHCP Message\n\t\tLength: "+ len +"\n\t\tMessage: "+s.toString()+"\n");
                break;
            case "39":
                o.append("\tOption: (57) Maximum DHCP Message Size\n\t\tLength: 2\n\t\tMaximum DHCP Message Size: "+hexToDecimal(option.get(2)+option.get(3))+"\n");
                break;
            case "3d":
                o.append("\tOption: (61) Client identifier\n\t\tLength: "+ len+"\n\t\tHardware type: Ethernet (0x01)\n\t\tClient MAC address: "+option.get(3)+":"+option.get(4)+":"+option.get(5)+":"+option.get(6)+":"+option.get(7)+":"+option.get(8)+"\n");
                break;
            case "42":
                StringBuilder s1 = new StringBuilder();
                for (int i = 0; i < len; i++){
                    s1.append(hexTotext(option.get(i+2)));
                }
                o.append("\tOption: (66) TFTP Server Name\n\t\tLength: "+ len+"\n\t\tTFTP Server Name: "+s1.toString()+"\n");
                break;
            case "43":
                StringBuilder s2 = new StringBuilder();
                for (int i = 0; i < len; i++){
                    s2.append(hexTotext(option.get(i+2)));
                }
                o.append("\tOption: (67) Bootfile Name\n\t\tLength: "+len+"\n\t\tBootfile Name: "+s2.toString()+"\n");
                break;
            default:
                return ParameterRequestListSolver(String.join("", option));
        }
        return o.toString();
    }

    public String ParameterRequestListSolver(String hex){
        /**Fonction qui permet de déterminer les options des du Parameter Request**/
        switch(hexToDecimal(hex)){
            case 0: return "Pad	";
            case 1: return "Subnet Mask	";
            case 2: return "Time Offset	";
            case 3: return "Router	";
            case 4: return "Time Server	";
            case 5: return "Name Server	";
            case 6: return "Domain Server	";
            case 7: return "Log Server	";
            case 8: return "Quotes Server	";
            case 9: return "LPR Server	";
            case 10: return "Impress Server	";
            case 11: return "RLP Server	";
            case 12: return "Hostname	";
            case 13: return "Boot File Size	";
            case 14: return "Merit Dump File	";
            case 15: return "Domain Name	";
            case 16: return "Swap Server	";
            case 17: return "Root Path	";
            case 18: return "Extension File	";
            case 19: return "Forward On/Off	";
            case 20: return "SrcRte On/Off	";
            case 21: return "Policy Filter	";
            case 22: return "Max DG Assembly	";
            case 23: return "Default IP TTL	";
            case 24: return "MTU Timeout	";
            case 25: return "MTU Plateau	";
            case 26: return "MTU Interface	";
            case 27: return "MTU Subnet	";
            case 28: return "Broadcast Address	";
            case 29: return "Mask Discovery	";
            case 30: return "Mask Supplier	";
            case 31: return "Router Discovery	";
            case 32: return "Router Request	";
            case 33: return "Static Route	";
            case 34: return "Trailers	";
            case 35: return "ARP Timeout	";
            case 36: return "Ethernet	";
            case 37: return "Default TCP TTL	";
            case 38: return "Keepalive Time	";
            case 39: return "Keepalive Data	";
            case 40: return "NIS Domain	";
            case 41: return "NIS Servers	";
            case 42: return "NTP Servers	";
            case 43: return "Vendor Specific	";
            case 44: return "NETBIOS Name Srv	";
            case 45: return "NETBIOS Dist Srv	";
            case 46: return "NETBIOS Node Type	";
            case 47: return "NETBIOS Scope	";
            case 48: return "X Window Font	";
            case 49: return "X Window Manager	";
            case 50: return "Address Request	";
            case 51: return "Address Time	";
            case 52: return "Overload	";
            case 53: return "DHCP Msg Type	";
            case 54: return "DHCP Server Id	";
            case 55: return "Parameter List	";
            case 56: return "DHCP Message	";
            case 57: return "DHCP Max Msg Size	";
            case 58: return "Renewal Time	";
            case 59: return "Rebinding Time	";
            case 60: return "Class Id	";
            case 61: return "Client Id	";
            case 62: return "NetWare/IP Domain	";
            case 63: return "NetWare/IP Option	";
            case 64: return "NIS-Domain-Name	";
            case 65: return "NIS-Server-Addr	";
            case 66: return "Server-Name	";
            case 67: return "Bootfile-Name	";
            case 68: return "Home-Agent-Addrs	";
            case 69: return "SMTP-Server	";
            case 70: return "POP3-Server	";
            case 71: return "NNTP-Server	";
            case 72: return "WWW-Server	";
            case 73: return "Finger-Server	";
            case 74: return "IRC-Server	";
            case 75: return "StreetTalk-Server	";
            case 76: return "STDA-Server	";
            case 77: return "User-Class	";
            case 78: return "Directory Agent	";
            case 79: return "Service Scope	";
            case 80: return "Rapid Commit	";
            case 81: return "Client FQDN	";
            case 82: return "Relay Agent Information	";
            case 83: return "iSNS	";
            case 84: return "REMOVED/Unassigned	";
            case 85: return "NDS Servers	";
            case 86: return "NDS Tree Name	";
            case 87: return "NDS Context	";
            case 88: return "BCMCS Controller Domain Name list	";
            case 89: return "BCMCS Controller IPv4 address option	";
            case 90: return "Authentication	";
            case 91: return "client-last-transaction-time option	";
            case 92: return "associated-ip option	";
            case 93: return "Client System	";
            case 94: return "Client NDI	";
            case 95: return "LDAP	";
            case 96: return "REMOVED/Unassigned	";
            case 97: return "UUID/GUID	";
            case 98: return "User-Auth	";
            case 99: return "GEOCONF_CIVIC	";
            case 100: return "PCode	";
            case 101: return "TCode	";
            case 102: return "REMOVED/Unassigned	";
            case 103: return "REMOVED/Unassigned	";
            case 104: return "REMOVED/Unassigned	";
            case 105: return "REMOVED/Unassigned	";
            case 106: return "REMOVED/Unassigned	";
            case 107: return "REMOVED/Unassigned	";
            case 108: return "IPv6-Only Preferred	";
            case 109: return "OPTION_DHCP4O6_S46_SADDR	";
            case 110: return "REMOVED/Unassigned	";
            case 111: return "Unassigned	";
            case 112: return "Netinfo Address	";
            case 113: return "Netinfo Tag	";
            case 114: return "DHCP Captive-Portal	";
            case 115: return "REMOVED/Unassigned	";
            case 116: return "Auto-Config	";
            case 117: return "Name Service Search	";
            case 118: return "Subnet Selection Option	";
            case 119: return "Domain Search	";
            case 120: return "SIP Servers DHCP Option	";
            case 121: return "Classless Static Route Option	";
            case 122: return "CCC	";
            case 123: return "GeoConf Option	";
            case 124: return "V-I Vendor Class	";
            case 125: return "V-I Vendor-Specific Information	";
            case 126: return "Removed/Unassigned	";
            case 127: return "Removed/Unassigned	";
            case 128: return "PXE - undefined (vendor specific)	";
            case 129: return "PXE - undefined (vendor specific)	";
            case 130: return "PXE - undefined (vendor specific)	";
            case 131: return "Remote statistics server IP address	";
            case 132: return "PXE - undefined (vendor specific)	";
            case 133: return "IEEE 802.1D/p Layer 2 Priority	";
            case 134: return "Diffserv Code Point (DSCP) for VoIP signalling and media streams";
            case 135: return "HTTP Proxy for phone-specific applications";
            case 136: return "OPTION_PANA_AGENT	";
            case 137: return "OPTION_V4_LOST	";
            case 138: return "OPTION_CAPWAP_AC_V4	";
            case 139: return "OPTION-IPv4_Address-MoS	";
            case 140: return "OPTION-IPv4_FQDN-MoS	";
            case 141: return "SIP UA Configuration Service Domains	";
            case 142: return "OPTION-IPv4_Address-ANDSF	";
            case 143: return "OPTION_V4_SZTP_REDIRECT	";
            case 144: return "GeoLoc	";
            case 145: return "FORCERENEW_NONCE_CAPABLE	";
            case 146: return "RDNSS Selection	";
            case 147: return "OPTION_V4_DOTS_RI	";
            case 148: return "OPTION_V4_DOTS_ADDRESS	";
            case 149: return "Unassigned	";
            case 150: return "TFTP server address	";
            case 151: return "status-code	";
            case 152: return "base-time	";
            case 153: return "start-time-of-state	";
            case 154: return "query-start-time	";
            case 155: return "query-end-time	";
            case 156: return "dhcp-state	";
            case 157: return "data-source	";
            case 158: return "OPTION_V4_PCP_SERVER	";
            case 159: return "OPTION_V4_PORTPARAMS	";
            case 160: return "Unassigned	";
            case 161: return "OPTION_MUD_URL_V4	";
            case 175: return "Etherboot (Tentatively Assigned - 2005-06-23)";
            case 176: return "IP Telephone (Tentatively Assigned - 2005-06-23)";
            case 177: return "PacketCable and CableHome (replaced by 122)	";
            case 208: return "PXELINUX Magic	";
            case 209: return "Configuration File	";
            case 210: return "Path Prefix	";
            case 211: return "Reboot Time	";
            case 212: return "OPTION_6RD	";
            case 213: return "OPTION_V4_ACCESS_DOMAIN	";
            case 220: return "Subnet Allocation Option	";
            case 221: return "Virtual Subnet Selection (VSS) Option	";
            case 224: return "Reserved (Private Use)	";
            case 254: return "Reserved (Private Use)	";
            case 255: return "End	";
            default: return "Unassigned	";
        }

    }

    public String DHCPMessageType(String message){
        /**Permet de retrouver le type du message
          message est sous la forme "xx"**/
        String str = "";
        switch(message){
            case "01":
                str = "Discover (1)";
                break;
            case "03":
                str = "Request (3)";
                break;
            case "04":
                str = "Decline (4)";
                break;
            case "07":
                str = "Release (7)";
                break;
            case "08":
                str = "Inform (8)";
                break;
            case "02":
                str = "Offer (2)";
                break;
            case "05":
                str = "ACK (5)";
                break;
            case "06":
                str = "NACK (6)";
                break;
            default:
                str = "Option inconnue.";
                break;
        }
        return str;
    }
    public String toString(){
        StringBuilder sb = new StringBuilder();
        //Dynamic Host Configuration Protocol
        sb.append("Dynamic Host Configuration Protocol ("+info+")\n");
        //Message Type
        sb.append("\tMessage type: ");
        switch(message_type){
            case "01":
                sb.append("Boot Request (1)\n");
                break;
            case "02":
                sb.append("Boot Reply (2)\n");
                break;
            default:
                return "Problème au niveau du message type";
        }
        String ub = ip.hexToBin(bootp_f);
        String msb = "";
        switch(ub.charAt(0)){
            case '0':
                msb = "Unicast";
                break;
            case '1':
                msb = "Broadcast";
                break;
        }
        int d = hexToDecimal(server_hname.toString());
        StringBuilder shn = new StringBuilder();
        if (d != 0){
            for (int i = 45 + encap_l; i < encap_l + 64 + 45; i++){
                shn.append(hexTotext(trame.get(i)));
            }
        }
        else if (d == 0){
            shn.append("not given");
        }

        d = hexToDecimal(bf_name.toString());
        StringBuilder bn = new StringBuilder();
        if (d != 0){
            for (int i = 45 + encap_l + 64; i < encap_l + 64 + 45 + 128; i++){
                bn.append(hexTotext(trame.get(i)));
            }
        }
        else if (d == 0){
            bn.append("not given");
        }
        sb.append("\tHardware type: Ethernet (0x01)\n\tHardware adress length: "+hard_l+"\n\tHops: "+hops+"\n\tTransaction ID: "+trans_id+"\n\tSeconds elapsed: "+sec_elapsed+"\n\tBootp flags: 0x0000 (Unicast)\n\t\t"+ub.charAt(0)+"... .... .... .... = Broadcast flag: "+msb+"\n\t\t.000 0000 0000 0000 = Reserved flags: 0x0000\n\tClient IP adress: "+c_ip+"\n\tYour (client) IP adress: "+y_ip+"\n\tNext server IP adress: "+next_ip+"\n\tRelay agent IP adress: "+relay_agent_ip+"\n\tClient MAC address: "+c_mac+"\n\tClient hardware address padding: 00000000000000000000\n\tServer host name "+shn.toString()+"\n\tBoot file name "+bn.toString()+"\n\tMagic cookie: DHCP\n"+opt.toString()+"\n");
        if (!trameValide){
            return "Erreur au niveau de la trame.";
        }
        try{
            ip.writeFile(path, sb.toString());
        }catch (IOException e){
            return "Problème au niveau de l'écriture du fichier.";
        }

        return sb.toString();
    }


}
