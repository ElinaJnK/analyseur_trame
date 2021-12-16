import java.util.*;
import java.util.Arrays;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class Udp{
    private int port_src;
    private int port_dest;
    private int longueur;
    private String checksum;
    private List<String> trame;
    private Ip ip;
    private Path path;

    public Udp(List<String> tr, Ip ip, Path path){
        trame=tr;
        this.path = path;
        this.ip = ip;
        int taille_ip = 13 + ip.getHl()*4;
        port_src=ip.hexToDecimal(trame.get(taille_ip+1)+trame.get(taille_ip+2));
        port_dest=ip.hexToDecimal(trame.get(taille_ip+3)+trame.get(taille_ip+4));
        if (!verificationPort(port_src, port_dest)){
            System.out.println("Le protocole encapsulé ne pourra pas être analysé.");
        }
        longueur=ip.hexToDecimal(trame.get(taille_ip+5)+trame.get(taille_ip+6));
        checksum="0x"+trame.get(taille_ip+7)+trame.get(taille_ip+8);
    }

    public int getP_src(){ return port_src;}
    public int getP_dest(){ return port_dest;}

    public boolean verificationPort(int portdest, int portsrc){
        /**Fonction qui va vérifier les ports et voir si notre code accepte les protocoles**/
    if (portdest == 53 || portsrc == 53){
    return true;
    }
    if ((portdest == 67 && portsrc == 68) || portdest == 68 && portsrc == 67) {
      return true;
    }
    return false;
    }

    public String toString(){
        StringBuilder s = new StringBuilder();
        s.append("User Datagram Protocol, Src Port: "+port_src+", Dst Port: "+port_dest+"\n");
        s.append("\tSource Port: "+port_src+"\n");
        s.append("\tDestination Port: "+port_dest+"\n");
        s.append("\tLength: "+longueur+"\n");
        s.append("\tChecksum: "+checksum+"\n");
        try{
            ip.writeFile(path, s.toString());
        }catch (IOException e){
            return "Problème au niveau de l' écriture du fichier.";
        }
        return s.toString();
    }
}
