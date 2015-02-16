import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.util.*;
import java.io.*;


public class rhParse 
{
//*********************main**********************

    public static void main(String[] args) throws Exception
    {  
          rhParse(args[0]);      
    }

//****************rhParse()**********************

    public static void rhParse(String fName) throws Exception 
    {
        FileWriter writer = new FileWriter("redhat.csv",true);
        writer.append("Release" + "," + "CVE" + "," + "Package" + "," + "FixVer" +"," +"URL" + "," + "\n");
          
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document doc = builder.parse(fName);
             
        NodeList definitionList = doc.getElementsByTagName("definition");
        for (int i = 0; i < definitionList.getLength(); ++i)
        {
           Element definition = (Element) definitionList.item(i);
           String distro = definition.getElementsByTagName("platform").item(0).getTextContent();
           String num = distro.substring(distro.length() -1);

           ArrayList<String> cveAList = new ArrayList<String>();
           ArrayList<String> URLList = new ArrayList<String>();
            
           NodeList cveList = definition.getElementsByTagName("cve");
           for (int j = 0; j < cveList.getLength(); ++j)
           {
              Element value = (Element) cveList.item(j);
              String cveNum = value.getFirstChild().getNodeValue();
              String link = value.getAttribute("href");

              cveAList.add(cveNum);
              URLList.add(link);
              
              NodeList valueList = definition.getElementsByTagName("criterion");
              for (int k = 0; k < valueList.getLength(); ++k)
              {
                 Element value2 = (Element) valueList.item(k);
                 String valueType = value2.getAttribute("comment");
                 
                 if(valueType.contains("is earlier than"))
                 {
                    String fixVer = valueType;
                    String[] pkgNfix = fixVer.split(" is earlier than");
                    String pkgName = pkgNfix[0];
                    String fix = pkgNfix[1];
                    
                    for(int z = 0; z< cveAList.size(); z++)
                    {
                       if(!fix.contains("el"+num))
                       {
                          continue;
                       }
                       else
                       {                       
                          writer.append( distro+","+ cveAList.get(z) +","+ pkgName + ","+ fix +"," + URLList.get(z) + "," + "\n");
                       }
                    }    
                 }
                  
              } 
           } 
         
        }
        writer.flush();
	    writer.close();
    }
}