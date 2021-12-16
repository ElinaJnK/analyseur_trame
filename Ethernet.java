import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public class Ethernet {
    //Adresse MAC Destination
    private String mac_dest;
    //Adresse MAC Source
    private String mac_src;
    //Type
    private String type;
    //Trame analysée
    private List<String> trame;
    //Donne le chemin pour ecrire dans un fichier
    private Path path;


    public Ethernet(List<String> tr, Path path){
        trame=tr;
        this.path = path;
        mac_dest = trame.get(0)+":"+trame.get(1)+":"+trame.get(2)+":"+trame.get(3)+":"+trame.get(4)+":"+trame.get(5);
        mac_src = trame.get(6)+":"+trame.get(7)+":"+trame.get(8)+":"+trame.get(9)+":"+trame.get(10)+":"+trame.get(11);
        type = trame.get(12) + trame.get(13);
    }

    public String getMacDest() {
        /**Fonction qui permet de récupérer l'adresse MAC destination**/
        return mac_dest;
    }

    public String getMacSrc() {
        /**Fonction qui permet de récupérer l'adresse MAC source**/
        return mac_src;
    }

    public String getType() {
        /**Fonction qui va permettre de récupérer le type**/
        return type;
    }

    private static void writeFile(Path path, String content) throws IOException {
        /**Fonction qui va écrire dans un fichier**/
        Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Ethernet II, Src: " + mac_src + ", Dst: " + mac_dest + "\n");
        s.append("\tDestination: " + mac_dest + "\n");
        s.append("\tSource: " + mac_src + "\n");
        String str = "";
        if (type.equals("0800")){
            str = "IPv4 0x0800";
        }
        if (type.equals("0806")){
            str = "ARP 0x0806";
        }
        s.append("\tType: " + str + "\n");
        try{
            writeFile(path, s.toString());
        }catch (IOException e){
            return "Problème au niveau de l'écriture du fichier.";
        }
        return s.toString();

    }

}
