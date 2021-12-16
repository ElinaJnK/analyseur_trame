import java.io.*;
import java.util.Arrays;
import java.util.*;
import java.util.regex.*;
public class LireFichier{
    private String file;
    //Liste de trames
    private List<List<String>> listElem;
    //Liste des trames sans offset
    private List<List<String>> listTrame;
    //Liste qui contient une trame
    private List<String> listTmp;
    //Liste qui contient une trame sans offset
    private List<String> listTmp2;
    //Compteur qui va servir a verifier la trame
    private int cpt;

    public LireFichier(String file){
        this.file = file;
        listElem = new ArrayList<>();
        listTrame = new ArrayList<>();
        listTmp = new ArrayList<>();
        listTmp2 = new ArrayList<>();
        cpt = 0;
    }

    public void lectureFichier(){
        /**Fonction qui permet la lecture du fichier**/
        try(BufferedReader br = new BufferedReader(new FileReader(file))) {
            int i;
            String line;
            String[] tab;
            while ((line = br.readLine()) != null) {
                i = 0;
                tab = line.split(" ");
                while (tab.length > i){
                    if (tab[i].equals("0000")){
                        if (this.listTmp.size() != 0){
                            this.listElem.add(this.listTmp);
                            this.listTrame.add(this.listTmp2);
                            cpt = 0;
                        }
                        listTmp = new ArrayList<>();
                        listTmp2 = new ArrayList<>();
                        this.listTmp.add(tab[i]);
                    }

                    else{
                        try{
                            filtreLigne(tab[i],cpt);
                        }catch(Exception e){
                            System.out.println("Il y a une erreur au niveau de la longueur de la chaine.");
                            return;
                        }
                        filtreLigneSansOffset(tab[i]);
                    }
                    i++;
                }
                System.out.println(line);
            }
            if (this.listTmp.size() != 0){
                this.listElem.add(this.listTmp);
                this.listTrame.add(this.listTmp2);
            }
        }catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public void filtreLigne(String elem, int cpt) throws Exception{
        /**Fonction qui va faire le filtre sur chaque donnée et lancer une exception si la donnee est invalide.
          Si i = 0 on veut que la donnee soit sur 4 chiffres ou lettres
          autrement on veut que i soit sur 2 chiffres ou lettre**/
        if (Pattern.matches("[a-fA-F0-9]{2}", elem)){
            this.cpt++;
            this.listTmp.add(elem);
        }
        if (Pattern.matches("[a-fA-F0-9]{4}", elem)){
            int verif_offset = hexToDecimal(elem);
            if (cpt == verif_offset){
                this.listTmp.add(elem);
            }
            else{
                throw new Exception("Il y a une erreur au niveau de la taille de la chaine.");
            }
        }
    }

    public void filtreLigneSansOffset(String elem){
        if (Pattern.matches("[a-fA-F0-9]{2}", elem)){
            this.listTmp2.add(elem);
        }
    }

    public int hexToDecimal(String hex){
        /**Fonction qui permet de convertir un hexadecimal en int décimal**/
        return Integer.parseInt(hex,16);
    }

    public List<String> getListTrame(int i){
        /**Fonction qui permet de prendre la trame sur laquelle on travaille (trame sans offset)**/
        return listTrame.get(i);
    }

    public List<String> getListElem(int i){
        /**Fonction qui donne la trame avec les offsets**/
        return listElem.get(i);
    }

    public int size(){
        /**Retourne la taille de la trame actuelle**/
        return listTrame.size();
    }
}
