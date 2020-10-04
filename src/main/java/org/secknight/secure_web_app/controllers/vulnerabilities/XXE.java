package org.secknight.secure_web_app.controllers.vulnerabilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;

@RequestMapping("/xxe-interface")
public abstract class XXE {}

@Controller
class Controller_XXE extends XXE {
    @GetMapping
    public String home() { return "xxe"; }
}

@RestController
class RestController_XXE extends XXE {
    private static final Logger LOG = LoggerFactory.getLogger(RestController_XXE.class);

    @PostMapping(value="/restSecure",consumes = {MediaType.APPLICATION_XML_VALUE})
    public String secured(@RequestBody String input) {
        Document document = secureXMLParser(input);
        if (document!=null){
            return analyzeDocument(document);
        }
        return "Could not parse input";
    }

    @PostMapping(value="/restVulnerable",consumes = {MediaType.APPLICATION_XML_VALUE})
    public String vulnerable(@RequestBody String input) {
        System.out.println(input);
        Document document = vulnerableXMLParser(input);
        if (document!=null){
            return analyzeDocument(document);
        }
        return "Could not parse input";
    }


    /**
     * Analyze the parsed XML input to retrieve and store information
     * @param document XML Parsed Document
     * @return Output
     */
    private static String analyzeDocument(Document document){
        StringBuilder sb = new StringBuilder();
        NodeList nodeList = document.getDocumentElement().getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element elem = (Element) node;
                String ID = node.getAttributes().getNamedItem("ID").getNodeValue();

                // Get the value of all sub-elements.
                String firstname = elem.getElementsByTagName("Firstname")
                        .item(0).getChildNodes().item(0).getNodeValue();

                String lastname = elem.getElementsByTagName("Lastname").item(0)
                        .getChildNodes().item(0).getNodeValue();

                int age = Integer.parseInt(elem.getElementsByTagName("Age")
                        .item(0).getChildNodes().item(0).getNodeValue());

                double salary = Double.parseDouble(elem.getElementsByTagName("Salary")
                        .item(0).getChildNodes().item(0).getNodeValue());
                sb.append(ID).append(" ").append(firstname).append(" ").append(lastname).append(" ").append(age).append(" ").append(salary).append("<br>");

            }
        }
        return sb.toString();
    }

    private static Document vulnerableXMLParser(String xmlString) {
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

        //API to obtain DOM Document instance
        DocumentBuilder builder;
        try
        {
            //Create DocumentBuilder with default configuration
            builder = factory.newDocumentBuilder();

            //Parse the content to Document object
            return builder.parse(new InputSource(new StringReader(xmlString)));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    private static Document secureXMLParser(String xmlString) {
        //Parser that produces DOM object trees from XML content
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        String FEATURE = null;
        //API to obtain DOM Document instance
        DocumentBuilder builder;
        try
        {
            // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all
            // XML entity attacks are prevented
            // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
            FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
            factory.setFeature(FEATURE, true);

            // If you can't completely disable DTDs, then at least do the following:
            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
            // JDK7+ - http://xml.org/sax/features/external-general-entities
            FEATURE = "http://xml.org/sax/features/external-general-entities";
            factory.setFeature(FEATURE, false);

            // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
            // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
            // JDK7+ - http://xml.org/sax/features/external-parameter-entities
            FEATURE = "http://xml.org/sax/features/external-parameter-entities";
            factory.setFeature(FEATURE, false);

            // Disable external DTDs as well
            FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
            factory.setFeature(FEATURE, false);

            // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            // And, per Timothy Morgan: "If for some reason support for inline DOCTYPEs are a requirement, then
            // ensure the entity settings are disabled (as shown above) and beware that SSRF attacks
            // (http://cwe.mitre.org/data/definitions/918.html) and denial
            // of service attacks (such as billion laughs or decompression bombs via "jar:") are a risk."


            //Create DocumentBuilder with default configuration
            builder = factory.newDocumentBuilder();

            //Parse the content to Document object
            return builder.parse(new InputSource(new StringReader(xmlString)));

        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            LOG.info("ParserConfigurationException was thrown. The feature '" + FEATURE
                    + "' is probably not supported by your XML processor.");
        } catch (SAXException e) {
            // On Apache, this should be thrown when disallowing DOCTYPE
            LOG.warn("A DOCTYPE was passed into the XML document");
        } catch (IOException e) {
            // XXE that points to a file that doesn't exist
            LOG.error("IOException occurred, XXE may still possible: " + e.getMessage());
        }
        return null;
    }
}

