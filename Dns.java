import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.ArrayList;

public class Dns {
    //Trame
    private List<String> trame;
    private String Transaction_ID;
    private String Flags;
    private int Questions;
    private int Answer_RRs;
    private int Authority_RRs;
    private int Additional_RRs;
    private Ip ip;
    //Longueur des couches qui encapsulent le protocole DNS
    private int encap_l;
    StringBuilder name = new StringBuilder();
    int type;
    String classe;
    int ttl;
    int data;
    int preference = 0;
    StringBuilder Mail_Exchange = new StringBuilder();
    StringBuilder Name_Server = new StringBuilder();
    StringBuilder cname = new StringBuilder();
    StringBuilder AAAA_Adress = new StringBuilder();
    StringBuilder Adress = new StringBuilder();
    StringBuilder Primary_name_server = new StringBuilder();
    StringBuilder Responsible_authority_mailbox = new StringBuilder();
    int Serial_Number = 0;
    int Refresh_Interval = 0;
    int Retry_Interval = 0;
    int Expire_limit = 0;
    int Minimum_TTL = 0;
    private Path path;

    public Dns(List<String> tr, Ip ip, Path path) {
        this.ip = ip;
        encap_l= 13+ (ip.getHl()*4) +8;
        trame = tr;
        this.path = path;
        Transaction_ID = "0x" + trame.get(encap_l+ 1) + trame.get(encap_l+ 2);
        Flags = "0x"+trame.get(encap_l+ 3) + trame.get(encap_l + 4);
        Questions = ip.hexToDecimal(trame.get(encap_l+ 5) + trame.get(encap_l + 6));
        Answer_RRs = ip.hexToDecimal(trame.get(encap_l+ 7) + trame.get(encap_l + 8));
        Authority_RRs = ip.hexToDecimal(trame.get(encap_l+ 9) + trame.get(encap_l+ 10));
        Additional_RRs = ip.hexToDecimal(trame.get(encap_l+ 11) + trame.get(encap_l+ 12));
    }

    public String hexTobin(String hex) {
        String res= Integer.toBinaryString(Integer.parseInt(hex, 16));
        if(res.length()<16){
            String z="";
            for(int j=0; j<(16-res.length()); j++){
                z +="0";
            }
            res=z+res;
        }
        return res;
    }


    public String hexTotext(String hex) {
        /**Fonction qui transforme des caractère héxadécimal en caractères ASCII**/
        StringBuilder output = new StringBuilder("");

        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }

        return output.toString();
    }

    public String time(int totalSecs){
        /**Fonction qui permet de donner le temps**/
        int days = totalSecs / (24 * 3600);
        int hours = totalSecs / 3600;
        int minutes = (totalSecs % 3600) / 60;
        int seconds = totalSecs % 60;
        if(days==0){
            if(hours==0){
                if(minutes==0){
                    if(seconds==0 || seconds==1)
                        return String.format("%02d second", seconds);
                    return String.format("%02d seconds", seconds);
                }
                if(minutes==1){
                    if(seconds==0)
                        return String.format("%02d minute", minutes);
                    if(seconds==1)
                        return String.format("%02d minute, %02d second", minutes, seconds);
                    return String.format("%02d minute, %02d seconds", minutes, seconds);
                }
                else{
                    if(seconds==0)
                        return String.format("%02d minutes", minutes);
                    if(seconds==1)
                        return String.format("%02d minutes, %02d second", minutes, seconds);
                    return String.format("%02d minutes, %02d seconds", minutes, seconds);
                }
            }
            if(hours==1){
                if(minutes==0){
                    if(seconds==0)
                        return String.format("%02d hour", hours);
                    if(seconds==1)
                        return String.format("%02d hour, %02d minute, %02d second", hours, minutes, seconds);
                    return String.format("%02d hour, %02d minute, %02d seconds", hours, minutes, seconds);
                }
                if(minutes==1){
                    if(seconds==0)
                        return String.format("%02d hour, %02d minute", hours, minutes);
                    if(seconds==1)
                        return String.format("%02d hour, %02d minute, %02d second", hours, minutes, seconds);
                    return String.format("%02d hour, %02d minute, %02d seconds", hours, minutes, seconds);
                }
                else{
                    if(seconds==0)
                        return String.format("%02d hour, %02d minutes", hours, minutes);
                    if(seconds==1)
                        return String.format("%02d hour, %02d minutes, %02d second", hours, minutes, seconds);
                    return String.format("%02d hour, %02d minutes, %02d seconds", hours, minutes, seconds);
                }
            }
            else{
                if(minutes==0){
                    if(seconds==0)
                        return String.format("%02d hours", hours);
                    if(seconds==1)
                        return String.format("%02d hours, %02d minute, %02d second", hours, minutes, seconds);
                    return String.format("%02d hours, %02d minute, %02d seconds", hours, minutes, seconds);
                }
                if(minutes==1){
                    if(seconds==0)
                        return String.format("%02d hours, %02d minute", hours, minutes);
                    if(seconds==1)
                        return String.format("%02d hours, %02d minute, %02d second", hours, minutes, seconds);
                    return String.format("%02d hours, %02d minute, %02d seconds", hours, minutes, seconds);
                }
                else{
                    if(seconds==0)
                        return String.format("%02d hours, %02d minutes", hours, minutes);
                    if(seconds==1)
                        return String.format("%02d hours, %02d minutes, %02d second", hours, minutes, seconds);
                    return String.format("%02d hours, %02d minutes, %02d seconds", hours, minutes, seconds);
                }
            }
        }
        if(days==1)
            return String.format("%d day",days);
        return String.format("%d days",days);
    }

    public void flagSolver(StringBuilder st){
        /**Fonction qui permet de resoudre le champ flag.**/
        String s=hexTobin(Flags.substring(2));

        if(s.substring(1, 5).equals("0000"))
            st.append("Query");
        if(s.substring(1, 5).equals("0001"))
            st.append("IQuery");
        if(s.substring(1, 5).equals("0010"))
            st.append("Status");
        if(s.substring(1, 5).equals("0011"))
            st.append("Unassigned");
        if(s.substring(1, 5).equals("0100"))
            st.append("Notify");
        if(s.substring(1, 5).equals("0101"))
            st.append("Update");
        if(s.substring(1, 5).equals("0110"))
            st.append("DNS Stateful Operations (DSO)");

        if(s.charAt(0)=='0')
            st.append("\n");
        else{
            if(s.charAt(0)=='1')
                st.append(" response, ");
            if(s.substring(12).equals("0000"))
                st.append("NOERROR\n");
            if(s.substring(12).equals("0001"))
                st.append("FORMERR\n");
            if(s.substring(12).equals("0010"))
                st.append("SERVFAIL\n");
            if(s.substring(12).equals("0011"))
                st.append("NXDOMAIN\n");
            if(s.substring(12).equals("0100"))
                st.append("NOTIMP\n");
            if(s.substring(12).equals("0101"))
                st.append("REFUSED\n");
            if(s.substring(12).equals("0110"))
                st.append("YXDOMAIN\n");
            if(s.substring(12).equals("0111"))
                st.append("XRRSET\n");
            if(s.substring(12).equals("1000"))
                st.append("NOTAUTH\n");
            if(s.substring(12).equals("1001"))
                st.append("NOTZONE\n");
        }
        if(s.charAt(0)=='0')
            st.append("\t\t0... .... .... .... = Response: Message is a query\n");
        if(s.charAt(0)=='1')
            st.append("\t\t1... .... .... .... = Response: Message is a response\n");
        if(s.substring(1, 5).equals("0000"))
            st.append("\t\t.000 0... .... .... = Opcode: Standard query (0)\n");
        if(s.substring(1, 5).equals("0001"))
            st.append("\t\t.000 1... .... .... = Opcode: IQuery (1)\n");
        if(s.substring(1, 5).equals("0010"))
            st.append("\t\t.001 0... .... .... = Opcode: Status (2)\n");
        if(s.substring(1, 5).equals("0100"))
            st.append("\t\t.010 0... .... .... = Opcode: Notify (4)\n");
        if(s.substring(1, 5).equals("0101"))
            st.append("\t\t.010 1... .... .... = Opcode: Update (5)\n");
        if(s.substring(1, 5).equals("0110"))
            st.append("\t\t.011 0... .... .... = Opcode: DNS Stateful Operations (DSO) (6)\n");

        //Dans le cas d'une question
        if(s.charAt(0)=='0'){
            if(s.charAt(6)=='0')
                st.append("\t\t.... ..0. .... .... = Truncated: Message is not truncated\n");
            if(s.charAt(6)=='1')
                st.append("\t\t.... ..1. .... .... = Truncated: Message is truncated\n");
            if(s.charAt(7)=='0')
                st.append("\t\t.... ...0 .... .... = Recursion desired: Not do query recursively\n");
            if(s.charAt(7)=='1')
                st.append("\t\t.... ...1 .... .... = Recursion desired: Do query recursively\n");
            if(s.charAt(9)=='0')
                st.append("\t\t.... .... .0.. .... = Z: reserved (0)\n");
            if(s.charAt(9)=='1')
                st.append("\t\t.... .... .1.. .... = Z: not reserved (1)\n");
            if(s.charAt(11)=='0')
                st.append("\t\t.... .... ...0 .... = Non-authenticated data: Unacceptable\n");
            if(s.charAt(11)=='1')
                st.append("\t\t.... .... ...1 .... = authenticated data: acceptable\n");
        }
        //Dans le cas d'une rep
        if(s.charAt(0)=='1'){
            if(s.charAt(5)=='0')
                st.append("\t\t.... .0.. .... .... = Authoritative: Server is not an authority for domain\n");
            if(s.charAt(5)=='1')
                st.append("\t\t.... .1.. .... .... = Authoritative: Server is an authority for domain\n");
            if(s.charAt(6)=='0')
                st.append("\t\t.... ..0. .... .... = Truncated: Message is not truncated\n");
            if(s.charAt(6)=='1')
                st.append("\t\t.... ..1. .... .... = Truncated: Message is truncated\n");
            if(s.charAt(7)=='0')
                st.append("\t\t.... ...0 .... .... = Recursion desired: Not do query recursively\n");
            if(s.charAt(7)=='1')
                st.append("\t\t.... ...1 .... .... = Recursion desired: Do query recursively\n");
            if(s.charAt(8)=='0')
                st.append("\t\t.... .... 0... .... = Recursion available: Server can not do recursive queries\n");
            if(s.charAt(8)=='1')
                st.append("\t\t.... .... 1... .... = Recursion available: Server can do recursive queries\n");
            if(s.charAt(9)=='0')
                st.append("\t\t.... .... .0.. .... = Z: reserved (0)\n");
            if(s.charAt(10)=='0')
                st.append("\t\t.... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server\n");
            if(s.charAt(10)=='1')
                st.append("\t\t.... .... ..1. .... = Answer authenticated: Answer/authority portion was authenticated by the server\n");
            if(s.charAt(11)=='0')
                st.append("\t\t.... .... ...0 .... = Non-authenticated data: Unacceptable\n");
            if(s.charAt(11)=='1')
                st.append("\t\t.... .... ...1 .... = Authenticated data: acceptable\n");
            if(s.substring(12).equals("0000"))
                st.append("\t\t.... .... .... 0000 = Reply code: NOERROR (0)\n");
            if(s.substring(12).equals("0001"))
                st.append("\t\t.... .... .... 0001 = Reply code: FORMERR (1)\n");
            if(s.substring(12).equals("0010"))
                st.append("\t\t.... .... .... 0010 = Reply code: SERVFAIL (2)\n");
            if(s.substring(12).equals("0011"))
                st.append("\t\t.... .... .... 0011 = Reply code: NXDOMAIN (3)\n");
            if(s.substring(12).equals("0100"))
                st.append("\t\t.... .... .... 0100 = Reply code: NOTIMP (4)\n");
            if(s.substring(12).equals("0101"))
                st.append("\t\t.... .... .... 0101 = Reply code: REFUSED (5)\n");
            if(s.substring(12).equals("0110"))
                st.append("\t\t.... .... .... 0110 = Reply code: YXDOMAIN (6)\n");
            if(s.substring(12).equals("0111"))
                st.append("\t\t.... .... .... 0111 = Reply code: XRRSET (7)\n");
            if(s.substring(12).equals("1000"))
                st.append("\t\t.... .... .... 1000 = Reply code: NOTAUTH (8)\n");
            if(s.substring(12).equals("1001"))
                st.append("\t\t.... .... .... 1001 = Reply code: NOTZONE (9)\n");
        }
    }

    public void typeQuestion_title(StringBuilder st){
        /**Fonction qui permet de resoudre le type dans le titre du champ Questions**/
        if(type==1)
            st.append("A, ");
        if(type==2)
            st.append("NS, ");
        if(type==5)
            st.append("CNAME, ");
        if(type==6)
            st.append("SOA, ");
        if(type==15)
            st.append("MX,  ");
        if(type==28)
            st.append("AAAA, ");
    }

    public void typeSolver(StringBuilder st){
        /**Fonction qui permet de resoudre le type**/
        if(type==1)
            st.append("\t\t\tType: A (Host Address) (1)\n");
        if(type==2)
            st.append("\t\t\tType: NS (authoritative Name Server) (2)\n");
        if(type==5)
            st.append("\t\t\tType: CNAME (Canonical NAME for an alias) (5)\n");
        if(type==6)
            st.append("\t\t\tType: SOA (Start Of Authority) (6)\n");
        if(type==15)
            st.append("\t\t\tType: MX (Mail eXchange) (15)\n");
        if(type==28)
            st.append("\t\t\tType: AAAA (IPv6 Address) (28)\n");
    }

    public void typeAnswers_title(StringBuilder st){
        /**Fonction qui permet de resoudre le type dans le titre du champ Answers**/
        if(type==1)
            st.append("A, class IN, addr "+Adress+"\n");
        if(type==2)
            st.append("NS, class IN, ns "+hexTotext(Name_Server.toString())+"\n");
        if(type==5)
            st.append("CNAME, class IN, cname "+hexTotext(cname.toString())+"\n");
        if(type==6)
            st.append("SOA, class IN, mname "+hexTotext(Primary_name_server.toString())+"\n");
        if(type==15)
            st.append("MX, class IN, preference "+preference+", mx "+hexTotext(Mail_Exchange.toString())+"\n");
        if(type==28)
            st.append("AAAA, class IN, addr "+AAAA_Adress+"\n");
    }

    public void typeValue(StringBuilder st){
        /**Fonction qui indentifie et donne la valeur selon le type**/
        if(type==1)
            st.append("\t\t\tAddress: "+Adress+"\n");
        if(type==2)
            st.append("\t\t\tName Server: "+hexTotext(Name_Server.toString())+"\n");
        if(type==5)
            st.append("\t\t\tCNAME: "+hexTotext(cname.toString())+"\n");
        if(type==6){
            st.append("\t\t\tPrimary_name_server: "+hexTotext(Primary_name_server.toString())+"\n");
            st.append("\t\t\tResponsible authority's mailbox: "+hexTotext(Responsible_authority_mailbox.toString())+"\n");
            st.append("\t\t\tSerial Number: "+Serial_Number+"\n");
            st.append("\t\t\tRefresh Interval: "+Refresh_Interval+" ("+time(Refresh_Interval)+")\n");
            st.append("\t\t\tRetry Interval: "+Retry_Interval+" ("+time(Retry_Interval)+")\n");
            st.append("\t\t\tExpire limit: "+Expire_limit+" ("+time(Expire_limit)+")\n");
            st.append("\t\t\tMinimum TTL: "+Minimum_TTL+" ("+time(Minimum_TTL)+")\n");
        }
        if(type==15){
            st.append("\t\t\tPreference: "+preference+"\n");
            st.append("\t\t\tMail Exchange: "+hexTotext(Mail_Exchange.toString())+"\n");
        }
        if(type==28)
            st.append("\t\t\tAAAA Address: "+AAAA_Adress+"\n");
    }

    public int binTodec(String bin){
        /**Fonction qui donne un chiffre decimal a partir d'une String binaire**/
        Integer i = Integer.parseInt(bin,2);
        return i;
    }

    public int nameSolverbis(int i){
        /****/
        List<String> tmp=new ArrayList<>();
        int decalage=i+1;
        while(!(trame.get(decalage).equals("00"))){
            if(trame.get(decalage).charAt(0)=='c'){
                tmp.add(trame.get(decalage));
                tmp.add(trame.get(decalage+1));
                break;
            }else{
                tmp.add(trame.get(decalage));
                decalage++;
            }
        }
        if(trame.get(decalage).equals("00"))
            tmp.add(trame.get(decalage));
        return tmp.size();
    }

    public void nameSolver(int i, StringBuilder name){
        /**Fonction qui initialise les valeurs qui stockent un nom**/
        int decalage=i+1;
        while(!(trame.get(decalage).equals("00"))){
            String bin=hexTobin(trame.get(decalage)+trame.get(decalage+1));
            if(bin.substring(0,2).equals("11")){
                decalage=encap_l+binTodec(bin.substring(2))+1;
            }else{
                int p=1;
                if(name.length() > 0)
                    name.append("2e");

                while(p <= ip.hexToDecimal(trame.get(decalage))){
                    name.append(trame.get(decalage+p));
                    p++;
                }
                decalage=decalage+p;
            }
        }
    }

    public int answersSolver(int indice){
        /**Fonction qui détermine la taille des noms compressés dans la trame**/
        int i=indice;
        name.delete(0, name.length());
        nameSolver(i,name);
        i +=2;
        type=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2));
        i +=2;
        classe="0x"+trame.get(i+1)+trame.get(i+2);
        i +=2;
        ttl=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
        i +=4;
        data=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2));
        i +=2;

        //A
        if(type==1){
            Adress.delete(0, Adress.length());
            Adress.append(ip.hexToDecimal(trame.get(i+1))+"."+ip.hexToDecimal(trame.get(i+2))+"."+ip.hexToDecimal(trame.get(i+3))+"."+ip.hexToDecimal(trame.get(i+4)));
            i +=4;
        }
        //NS
        if(type==2){
            Name_Server.delete(0, Name_Server.length());
            nameSolver(i, Name_Server);
            i +=nameSolverbis(i);
        }
        //cname
        if(type==5){
            cname.delete(0, cname.length());
            nameSolver(i, cname);
            i +=nameSolverbis(i);
        }
        //SOA
        if(type==6){
            Primary_name_server.delete(0, Primary_name_server.length());
            nameSolver(i, Primary_name_server);
            i +=nameSolverbis(i);

            Responsible_authority_mailbox.delete(0, Responsible_authority_mailbox.length());
            nameSolver(i, Responsible_authority_mailbox);
            i +=nameSolverbis(i);

            Serial_Number=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
            i +=4;
            Refresh_Interval=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
            i +=4;
            Retry_Interval=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
            i +=4;
            Expire_limit=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
            i +=4;
            Minimum_TTL=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2)+trame.get(i+3)+trame.get(i+4));
            i +=4;
        }
        //MX
        if(type==15){
            preference =ip.hexToDecimal(trame.get(i+1))+ip.hexToDecimal(trame.get(i+2));
            i +=2;
            Mail_Exchange.delete(0, Mail_Exchange.length());
            nameSolver(i, Mail_Exchange);
            i +=nameSolverbis(i);
        }
        //AAAA
        if(type==28){
            AAAA_Adress.delete(0, AAAA_Adress.length());
            int k;
            String previous="";
            for(k=1; k<=14;k=k+2 ){
                String both=trame.get(i+k)+trame.get(i+k+1);
                int j=0;
                while(j<both.length() && both.charAt(j)=='0'){
                    j++;
                }
                if(AAAA_Adress.length()==0)
                    AAAA_Adress.append(both.substring(j));
                else{
                    if(both.substring(j).length()==0 && AAAA_Adress.length()>0){
                        if(previous.equals("0000"))
                            AAAA_Adress.append(both.substring(j));
                        else{
                            AAAA_Adress.append(":"+both.substring(j));
                        }
                        previous="0000";
                    }
                    else{
                        AAAA_Adress.append(":"+both.substring(j));
                        previous=both.substring(j);
                    }
                }
            }
            String both=trame.get(i+k)+trame.get(i+k+1);
            int j=0;
            while(j<both.length() && both.charAt(j)=='0'){
                j++;
            }
            if(AAAA_Adress.length()==0)
                AAAA_Adress.append(both.substring(j));
            else{
                if(both.substring(j).length()==0 && AAAA_Adress.length()>0){
                    if(previous.equals("0000"))
                        AAAA_Adress.append(both.substring(j));
                    else{
                        AAAA_Adress.append(":"+both.substring(j));
                    }
                    previous="0000";
                }
                else{
                    AAAA_Adress.append(":"+both.substring(j));
                    previous=both.substring(j);
                }
            }
            i +=16;
        }
        return i;
    }

    public String toString(){
        StringBuilder st=new StringBuilder();
        String s=hexTobin(Flags.substring(2));
        if(s.charAt(0)=='0'){
            st.append("Domain Name System (query)\n");
        }
        if(s.charAt(0)=='1'){
            st.append("Domain Name System (response)\n");
        }
        st.append("\tTransaction ID: "+Transaction_ID+"\n");
        st.append("\tFlags: "+Flags+" ");
        flagSolver(st);
        st.append("\tQuestions: "+Questions+"\n");
        st.append("\tAnswer RRs: "+Answer_RRs+"\n");
        st.append("\tAuthority RRs: "+Authority_RRs+"\n");
        st.append("\tAdditional RRs: "+Additional_RRs+"\n");


        int i=encap_l+13;
        //Queries
        if(Questions>0)
            st.append("\tQueries\n");
        for(int q=0; q<Questions; q++){
            name.delete(0, name.length());
            int decalage=i;
            while(!(trame.get(decalage).equals("00"))){
                int p=1;
                if(name.length() > 0)
                    name.append("2e");

                while(p <= ip.hexToDecimal(trame.get(decalage))){
                    name.append(trame.get(decalage+p));
                    p++;
                }
                decalage=decalage+p;
                i +=p;
            }

            type=ip.hexToDecimal(trame.get(i+1)+trame.get(i+2));
            classe="0x"+trame.get(i+3)+trame.get(i+4);
            st.append("\t\t"+hexTotext(name.toString())+": type ");
            typeQuestion_title(st);
            st.append("class IN\n");
            st.append("\t\t\tName: "+hexTotext(name.toString())+"\n");
            st.append("\t\t\t[Name Length: "+hexTotext(name.toString()).length()+"]\n");
            st.append("\t\t\t[Label Count: "+name.toString().split("2e").length+"]\n");
            typeSolver(st);
            st.append("\t\t\tClass: IN ("+classe+")\n");
        }
        //Answers 
        if(Answer_RRs>0)
            st.append("\tAnswers\n");
        i=i+4;
        for(int a=0; a<Answer_RRs; a++){
            i = answersSolver(i);

            st.append("\t\t"+hexTotext(name.toString())+": type ");
            typeAnswers_title(st);
            st.append("\t\t\tName: "+hexTotext(name.toString())+"\n");
            typeSolver(st);
            st.append("\t\t\tClass: IN ("+classe+")\n");
            st.append("\t\t\tTime to live: "+ttl+" ("+time(ttl)+")\n");
            st.append("\t\t\tData length: "+data+"\n");
            typeValue(st);
        }

        //Authority_RRs
        if(Authority_RRs>0)
            st.append("\tAuthoritative nameservers\n");
        for(int a=0; a<Authority_RRs; a++){
            i = answersSolver(i);

            st.append("\t\t"+hexTotext(name.toString())+": type ");
            typeAnswers_title(st);
            st.append("\t\t\tName: "+hexTotext(name.toString())+"\n");
            typeSolver(st);
            st.append("\t\t\tClass: IN ("+classe+")\n");
            st.append("\t\t\tTime to live: "+ttl+" ("+time(ttl)+")\n");
            st.append("\t\t\tData length: "+data+"\n");
            typeValue(st);
        }

        //Additional RRs
        if(Additional_RRs>0)
            st.append("\tAdditional nameservers\n");
        for(int a=0; a<Additional_RRs; a++){
            i = answersSolver(i);

            st.append("\t\t"+hexTotext(name.toString())+": type ");
            typeAnswers_title(st);
            st.append("\t\t\tName: "+hexTotext(name.toString())+"\n");
            typeSolver(st);
            st.append("\t\t\tClass: IN ("+classe+")\n");
            st.append("\t\t\tTime to live: "+ttl+" ("+time(ttl)+")\n");
            st.append("\t\t\tData length: "+data+"\n");
            typeValue(st);
        }
        try{
            ip.writeFile(path, st.toString());
        }catch (IOException e){
            return "Problème au niveau de l'écriture du fichier.";
        }
        return st.toString();
    }
}
