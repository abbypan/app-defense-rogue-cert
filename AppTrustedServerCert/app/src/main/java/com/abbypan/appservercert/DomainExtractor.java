package com.abbypan.appservercert;

import java.net.URI;
import com.google.common.net.InternetDomainName;

/**
 * Utility class for extracting domain information from URLs
 */
public class DomainExtractor {
    
    /**
     * Extracts the second-level domain (SLD) from a given URL
     * 
     * @param u the URL to extract domain from
     * @return the second-level domain in lowercase
     * @throws Exception if URL parsing fails
     */
    public static String read_sld(String u) throws Exception {
        URI uri = new URI(u);
        String host = uri.getHost();

        InternetDomainName internetDomainName = InternetDomainName.from(host).topPrivateDomain();
        String domain = internetDomainName.toString().toLowerCase();

        //    System.out.println(">>> url : " + u              );
        //   System.out.println(">>> host : " + host              );
        //  System.out.println(">>> domain : " + domain              );

        return domain;
    }
}
