import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

class Main {
    public static void main(String[] args) {
        System.out.println("Bonjour, bienvenue sur notre petit programme d'analyse de trame.\n Attention ! Notre programme est uniquement capable de reconnaître les couches Ethernet, IP, UDP, DNS et DHCP.\n");

        try{
            Thread.sleep(4000);
        }catch(InterruptedException ex)
        {
            Thread.currentThread().interrupt();
        }

        if (args.length != 2){
            System.out.println("Le nombre d'arguments spécifiés doit être de 2. Merci de relancer le programme sous la forme:\n java Main vosTrames.txt vosResultatsDAnalyse.txt\n");
            return;
        }
        LireFichier f = new LireFichier(args[0]);
        Path path = Paths.get(args[1]);
        f.lectureFichier();


        for(int i=0; i < f.size(); i++){
            List<String> trame = f.getListTrame(i);
            Ethernet eth = new Ethernet(trame, path);
            try{
                Thread.sleep(2000);
            }catch(InterruptedException ex)
            {
                Thread.currentThread().interrupt();
            }
            System.out.println("Trame "+(i+1)+":\n");
            System.out.println(eth.toString());
            if(trame.size() > 14 && (eth.getType().equals("0800") || eth.getType().equals("0806"))){
                Ip ip = new Ip(trame, path);
                System.out.println(ip.toString());

                if(trame.size() > 14 + ip.getHl()*4 && ip.getProtocol()==17){
                    Udp udp = new Udp(trame, ip, path);
                    System.out.println(udp.toString());

                    if(trame.size() > 14 + ip.getHl()*4 + 8){
                        if(udp.getP_src() == 67 || udp.getP_dest() == 67){
                            Dhcp dhcp = new Dhcp(trame, ip, udp, path);
                            System.out.println(dhcp.toString());
                        }
                        if(udp.getP_src() == 53 || udp.getP_dest() == 53){
                            Dns dns = new Dns(trame, ip, path);
                            System.out.println(dns.toString());
                        }
                    }
                }
            }
        }
    }
}
