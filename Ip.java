import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class Ip{
    //IP Src
    private String src;
    //IP Dest
    private String dest;
    //Version and Header Length
    private String version_hl;
    //Total Length
    private int totalLength;
    //Identification
    private String id;
    //Flags
    private String flags;
    //Time to Live
    private int ttl;
    //Protocol
    private String protocol;
    //Header Checksum
    private String header_checksum;
    //Trame
    private List<String> trame;
    //Booleen qui va verifier si la trame est valide
    private boolean trameValide;
    //Chemin qui va permettre d'ecrire dans un fichier
    private Path path;

    public Ip(List<String> tr, Path path){
        trame = tr;
        trameValide = true;
        this.path = path;
        src = ipBuilder(trame.get(26), trame.get(27), trame.get(28), trame.get(29));
        dest = ipBuilder(trame.get(30), trame.get(31), trame.get(32), trame.get(33));
        totalLength = hexToDecimal(trame.get(16)+ trame.get(17));
        version_hl = trame.get(14);
        id = "0x"+ trame.get(18) + trame.get(19) + " ("+hexToDecimal(trame.get(18) + trame.get(19))+")";
        flags = trame.get(20);
        ttl = hexToDecimal(trame.get(22));
        protocol = protocolSolver(trame.get(23));
        header_checksum = "0x" + trame.get(24) + trame.get(25);
        if (14 + totalLength != trame.size()){
            trameValide = false;
        }
    }

    public static void writeFile(Path path, String content) throws IOException {
        /**Fonction qui va écrire dans un fichier**/
        Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    public static String hexToBin(String hex){
        /**Fonction qui permet de convertir un hexadecimal en String binaire**/
        int num = Integer.parseInt(hex,16);
        return String.format("%8s", Integer.toBinaryString(num)).replace(" ", "0");
    }

    public int hexToDecimal(String hex){
        /**Fonction qui permet de convertir un hexadecimal en int décimal**/
        return Integer.parseInt(hex,16);
    }

    public int getProtocol(){
        /**Fonction qui retourne le protocole encapsulé par IP**/;
        return hexToDecimal(trame.get(23));
    }

    public String protocolSolver(String hex){
        /**Function qui retourne le protocole utilisé**/
        int code = hexToDecimal(hex);
        StringBuilder str = new StringBuilder();
        switch (code){
            case 1:
                str.append("ICMP (1)");
                break;
            case 2:
                str.append("IGMP (2)");
                break;
            case 6:
                str.append("TCP (6)");
                break;
            case 8:
                str.append("EGP (8)");
                break;
            case 9:
                str.append("IGP (9)");
                break;
            case 17:
                str.append("UDP (17)");
                break;
            case 36:
                str.append("XTP (36)");
                break;
            case 46:
                str.append("RSVP (46)");
                break;
            default:
                trameValide = false;
                return "Le protocole demandé ne fait pas partie des protocoles identifiés par notre programme";
        }
        return str.toString();
    }

    public String ipBuilder(String i1, String i2, String i3, String i4){
        /**Fonction qui permet de construire des adresse ip à partir de nombre héxadécimaux**/
        return hexToDecimal(i1)+"."+hexToDecimal(i2)+"."+hexToDecimal(i3)+"."+hexToDecimal(i4);
    }

    public int getHl(){
        /**Fonction qui permet de récupérer le Header Length**/
        int ht = hexToDecimal(Character.toString(version_hl.charAt(1)));
        return ht;      
    }
    public int binToDec(String bin){
        /**Fonction qui permet de passer d'une String binaire à un int décimal**/
        return Integer.parseInt(bin,2);  
    }
    public String toString(){
        StringBuilder sb = new StringBuilder();
        //Internet Protocol Version 4, Src: , Dest
        sb.append("Internet Protocol Version 4, Src: "+src+", Dst: "+dest);
        //0100 .... = Version: 4
        String n = hexToBin(version_hl);
        String version = n.substring(0,3);
        String hl = n.substring(4,7);
        int ver = binToDec(version);
        int h = binToDec(hl);
        sb.append("\t"+version+" .... = Version: "+ver+"\n");
        sb.append("\t.... "+hl+" = Header Length: "+(ver*h)+" bytes ("+h+")\n");
        //Differentiated Service Field
        sb.append("\tDifferentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)\n\t\t0000 00.. = Differentiated Services Codepoint: Default (0)\n\t\t.... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)\n");
        //Total Length:
        sb.append("\tTotal Length: "+totalLength+"\n");
        //Identification:
        sb.append("\tIdentification: "+id+"\n");
        //Flags: 0x21, More fragments
        StringBuilder flgs = new StringBuilder();
        sb.append("\tFlags: 0x"+flags);
        String bin = hexToBin(flags);
        switch(bin.charAt(0)){
            case '0':
                flgs.append("\t0... .... = Reserved bit: Not set\n");
                break;
            case '1':
                sb.append(", Reserved");
                flgs.append("\t1... .... = Reserved bit: Set\n");
                break;
            default:
                return "Il y a une erreur au niveau de Reserved Bit";
        }
        switch(bin.charAt(1)){
            case '0':
                flgs.append("\t.0.. .... = Don't fragment: Not set\n");
                break;
            case '1':
                sb.append(", Don't fragment");
                flgs.append("\t.1.. .... = Don't fragment: Set\n");
                break;
            default:
                return "Il y a une erreur au niveau de Don't fragment";
        }
        switch(bin.charAt(2)){
            case '0':
                flgs.append("\t..0. .... = Don't fragment: Not set\n");
                break;
            case '1':
                flgs.append("\t..1. .... = Don't fragment: Set\n");
                sb.append(", More fragments");
                break;
            default:
                return "Il y a une erreur au niveau de Reserved Bit";
        }
        sb.append("\n"+flgs.toString());
        //Time to Live
        sb.append("\tTime to Live: "+ttl+"\n");
        //Protocol
        sb.append("\tProtocol: "+protocol+"\n");

        //Header Checksum
        sb.append("\tHeader Checksum: "+header_checksum+"\n");
        //Source Adress
        sb.append("\tSource Address: "+src+"\n");
        //Destination Adress
        sb.append("\tDestination Address: "+dest+"\n");
        if (!trameValide){
            return "Il y a une erreur au niveau de la couche IP de la trame";
        }
        try{
            writeFile(path, sb.toString());
        }catch (IOException e){
            return "Problème au niveau de l'écriture du fichier.";
        }
        return sb.toString();
    }

}
