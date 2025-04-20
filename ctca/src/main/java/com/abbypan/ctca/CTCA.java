package com.abbypan.ctca;

import java.io.BufferedReader;
import java.io.File;
//import java.io.InputStream;
import java.io.InputStreamReader;
//import java.net.MalformedURLException;
import java.net.URL;
import java.net.URI;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
//import java.net.URLConnection;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
//import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.json.JSONArray;
//import org.apache.directory.shared.asn1.der.ASN1InputStream;
import org.json.JSONObject;

import com.google.common.net.InternetDomainName;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
//import oracle.security.crypto.cert.CRLDistPoint;

import org.apache.kerby.asn1.parse.Asn1ParseResult;
import org.apache.kerby.asn1.parse.Asn1Parser;
import org.apache.kerby.asn1.type.Asn1OctetString;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;


//@State(Scope.Benchmark)
//@OutputTimeUnit(TimeUnit.MILLISECONDS)
//@BenchmarkMode(Mode.All)
public class CTCA {
	
	private static JSONObject ctca_cache;
	
	public CTCA(String cache_file_name) throws Exception {
		ctca_cache = read_json_file(cache_file_name);
	}
	
//@Setup(Level.Iteration)
 public static void main(String[] args) throws Exception
 {   

	 //String trustStorePath = System.getProperty("java.home") + "/lib/security/cacerts";
	 //System.out.println("trustStorePath: " + trustStorePath);

	 //args: www.xxx.com, bypass/default/ctca, cache_file_name, appid

	 CTCA ctca = new CTCA(args[2]); 

	 long startTime = System.nanoTime();

	 HttpsURLConnection con = ctca.create_main_conn(args);
	 String res = ctca.get_content(con);

	 long endTime = System.nanoTime();
	 System.out.println(args[0] + "," + args[1] + "," + (endTime - startTime) / 1_000_000.0 );

	 //System.out.println(res+"\n");
 }   

 public static HttpsURLConnection create_main_conn(String[] para) throws Exception {
	 HttpsURLConnection con=null;

	 if(para[1].equals("default")) {
		 con = create_conn(para[0]);
	 }else if(para[1].equals("bypass")) {
		 con = create_bypass_conn(para[0]);
	 }else if(para[1].equals("ctca")) {
		 con = create_ctca_conn(para[0], para[3]);
	 }
	 return con;
 }

 private static HttpsURLConnection create_ctca_conn(String https_url, String appid) throws Exception {
	 //System.out.println("****** ctca ********"); 

	 //JSONObject ctca_cache = new JSONObject(ctca_cache_content);
	 //System.out.println(ctca_cache);
	 
     HttpsURLConnection con = create_conn(https_url);
     
     URI u = new URI(https_url);
     String host = u.getHost().toLowerCase();
     //System.out.println(">>> host : " + host );

     //long startTime = System.nanoTime();
     SSLSocketFactory sslSocketFactory = createCTCASslSocketFactory(host, appid);
     con.setSSLSocketFactory(sslSocketFactory);
     //long endTime = System.nanoTime();
     //System.out.println("createCTCASslSocketFactoryTime," + (endTime - startTime) / 1_000_000.0 + ",ms");

     return con;
 }
 
 private static HttpsURLConnection create_bypass_conn(String https_url) throws Exception {
	 //System.out.println("****** bypass ********"); 

     HttpsURLConnection con = create_conn(https_url);

     SSLSocketFactory sslSocketFactory = createBypassSslSocketFactory();
     con.setSSLSocketFactory(sslSocketFactory);

     HostnameVerifier hv = createBypassHostnameVerifier();
     con.setHostnameVerifier(hv);

     return con;
 }

 public static X509TrustManager get_default_trust_manager()  throws Exception {
     TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
     trustManagerFactory.init((KeyStore) null);

     X509TrustManager default_tm = null;
     for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
         if (trustManager instanceof X509TrustManager x509TrustManager) {
             default_tm = x509TrustManager;
             break;
         }
     }
     return default_tm;
 }

 @SuppressWarnings("null")
public static String checkCrtAtt(String h, X509Certificate ee, String appid) throws Exception {
	//System.out.println(">>> visit host : " + h);

	String sca = read_ca_dom(ee);
	//System.out.println(">>> TLS server cert CA dom : " + sca);

	//String dgstAlg = crtatt.getString("dgstalg");
	//System.out.println(">>> ctca dgst alg : " + dgstAlg);

	//String spk = calc_subject_pk_dgst(dgstAlg, ee);
	//System.out.println(">>> TLS server cert dgst spk : " + spk);
		 
	JSONArray ct = ctca_cache.getJSONArray("content");

	JSONObject ci, dj;
	String appid_read;
	JSONArray dom;
	JSONArray mcts =new JSONArray();
	JSONArray wcts =new JSONArray();

	for (int i = 0; i < ct.length(); i++) {
		ci = (JSONObject) ct.get(i);
		appid_read = (String) ci.get("appid");
		if(appid_read.equals(appid)) {
			JSONArray data = ci.getJSONArray("data");

			for(int j=0;j<data.length();j++) {
				dj = (JSONObject) data.get(j);

				dom = dj.getJSONArray("dom");
				for(int k=0; k<dom.length();k++) {
					String hk =  ((String) dom.get(k)).toLowerCase();

					if(hk.equals(h)) {
						JSONArray cadom = dj.getJSONArray("cadom");
						for(int z=0; z<cadom.length(); z++) {
							mcts.put(cadom.get(z));
						}
						//System.out.println(">>> ctca find dom match: " + dj);
					}else if(hk.startsWith("*")) {
						String dje = hk.replaceFirst("^\\*", "");
						if(h.endsWith(dje)) {
							JSONArray cadom = dj.getJSONArray("cadom");
							for(int z=0; z<cadom.length(); z++) {
								wcts.put(cadom.get(z));
							}
							//System.out.println(">>> ctca find wildcard dom match: " + dj);
						}
					}
				}


			}

			break;
		}

	}

	for(int j=0; j<mcts.length();j++) {
		String caj =  ((String) mcts.get(j)).toLowerCase();
		if(caj.equals(sca)) {
			//System.out.println(">>> ctca match sca success: " + caj);
			return "success";
		}else if(caj.startsWith("!")) {
			String caje = caj.replaceFirst("^\\!\\s*", "");
			if(caje.equals(sca)) {
				//System.out.println(">>> ctca should not match sca fail: " + caj);
				return "fail";
			}
		}
	}

	for(int j=0; j<wcts.length();j++) {
		String caj =  ((String) wcts.get(j)).toLowerCase();
		if(caj.equals(sca)) {
			//System.out.println(">>> ctca match sca success: " + caj);
			return "success";
		}else if(caj.startsWith("!")) {
			String caje = caj.replaceFirst("^\\!\\s*", "");
			if(caje.equals(sca)) {
				//System.out.println(">>> ctca should not match sca fail: " + caj);
				return "fail";
			}
		}
	}

	//System.out.println(">>> ctca : unknown");
	return "unknown";
}

public static JSONObject read_json_file(String cache_file_name) throws Exception {

	File cache_file = new File(cache_file_name);
	String ctca_cache_f =	 cache_file.getAbsolutePath();
	String ctca_content = new String(Files.readAllBytes(Paths.get(ctca_cache_f)));
	JSONObject cache = new JSONObject(ctca_content);

	return cache;
}

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

public static String read_crl(X509Certificate ee) throws Exception {
	byte[] crl = ee.getExtensionValue("2.5.29.31"); // CRL Distribution Points
	//  System.out.println(">>> Cert CRL : " + new BigInteger(1, crl).toString(16)                 );      


	Asn1OctetString octetString = new Asn1OctetString();           
	for(int i=0; i<2; i++) {
		octetString.decode(crl);
		//   Asn1.dump(octetString);
		crl = 	octetString.getValue();       
		octetString.decode(crl);
	}
	//  Asn1.dump(octetString);


	ByteBuffer buffer = ByteBuffer.wrap(octetString.getValue());
	Asn1ParseResult res = Asn1Parser.parse(buffer);
	byte[] crl_addr = res.readBodyBytes();
	String crl_str =         new String(crl_addr , StandardCharsets.UTF_8);
	//  System.out.println(">>> Cert CRL : " +        		crl_str        		);



	//   ASN1InputStream  crlis = new ASN1InputStream(crl);
	//com.hierynomus.asn1.types.constructed.ASN1Sequence s = crlis.iter;
	// byte[] crlr = crlis.readValue(crlis.readLength());
	//  ASN1Sequence  crlobj =  crlis.readObject();
	//     System.out.println(" >>> crl der size : " + crlis.readObject());

	//     ArrayList crlarr = (ArrayList) crlis.readObject().getValue();

	//   ASN1OctetString  crl_asn1 = new ASN1OctetString(crl);
	//    System.out.println(">>> Cert CRL : " +
	//       		 new BigInteger(1, crl_asn1.getValueBytes()).toString(16)

	// 		 new BigInteger(1, crl_asn1.getValue()).toString(16)
	//	                      );   
	// InputStream stream = new ByteArrayInputStream(exampleString.getBytes(StandardCharsets.UTF_8));
	// InputStream stream = new ByteArrayInputStream(crl);

	return crl_str;
}

public static String read_ca_dom(X509Certificate ee) throws Exception {
	return read_sld(read_crl(ee));
}

public static byte[] read_subject_pk(X509Certificate ee) {
	PublicKey pk = ee.getPublicKey();
	//System.out.println(">>> Cert Public Key Algorithm : " + pk.getAlgorithm());

	byte[] pk_der = pk.getEncoded();
	//System.out.println(">>> Cert Public Key Algorithm : " + HexUtil.bytesToHex(pk_der) );

	return pk_der;
}

public static byte[] digest( String hashName,  byte[] s) throws NoSuchAlgorithmException {
	MessageDigest digest = MessageDigest.getInstance(hashName);
	byte[] hash = digest.digest(s);
	return hash;
}

public static String calc_subject_pk_dgst(String dgstAlg, X509Certificate ee) throws Exception {
	byte[] pk_der = read_subject_pk(ee);
	//  System.out.println(">>> Cert Public Key DER : " + HexFormat.of().formatHex(pk_der) );

	byte[] dgst = digest(dgstAlg, pk_der);
	String s =  HexFormat.of().formatHex(dgst);
	//  System.out.println(">>> Cert Public Key Digest : " + s );

	return s;
}

//@Benchmark
private static  SSLSocketFactory createCTCASslSocketFactory(String host, String appid) throws Exception {
	X509TrustManager default_tm = get_default_trust_manager();

	TrustManager[] ctcaTrustManagers = new TrustManager[] { new X509TrustManager() {

		public X509Certificate[] getAcceptedIssuers() {
			return default_tm.getAcceptedIssuers();
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			default_tm.checkServerTrusted(chain, authType);

			X509Certificate ee = chain[0];

			try {
				String res = CTCA.checkCrtAtt(host, ee, appid);
				System.out.println(host + ",ctca!," + res);
				if(res.equals("fail")) {
					//throw new Exception("CTCA check: fail!");
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			default_tm.checkClientTrusted(chain, authType);
		}
	}

	};

	SSLContext sslContext = SSLContext.getInstance("TLS");
	sslContext.init(null, ctcaTrustManagers, new SecureRandom());
	return sslContext.getSocketFactory();
}

private static HostnameVerifier createBypassHostnameVerifier() {
	HostnameVerifier hv = new HostnameVerifier() {
		public boolean verify(String hostname, SSLSession session) { return true; }
	};
	return hv;
}

public static SSLSocketFactory createBypassSslSocketFactory() throws Exception {
	TrustManager[] byPassTrustManagers = new TrustManager[] { new X509TrustManager() {
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
		public void checkClientTrusted(X509Certificate[] chain, String authType) {
		}
		public void checkServerTrusted(X509Certificate[] chain, String authType) {
		}
	} };

	SSLContext sslContext = SSLContext.getInstance("TLS");
	sslContext.init(null, byPassTrustManagers, new SecureRandom());
	return sslContext.getSocketFactory();
}

private static HttpsURLConnection create_conn(String https_url) throws Exception {

	URL url;
	url = URI.create(https_url).toURL();
	HttpsURLConnection con = (HttpsURLConnection)url.openConnection();

	return con;
}



private void print_https_cert(HttpsURLConnection con) throws Exception {

	System.out.println("Response Code : " + con.getResponseCode());
	System.out.println("Cipher Suite : " + con.getCipherSuite());
	System.out.println("\n");



	Certificate[] certs = con.getServerCertificates();
	for(Certificate cert : certs){
		System.out.println("Cert Type : " + cert.getType());
		System.out.println("Cert Hash Code : " + cert.hashCode());
		System.out.println("Cert Public Key Algorithm : "
				+ cert.getPublicKey().getAlgorithm());
		System.out.println("Cert Public Key Format : "
				+ cert.getPublicKey().getFormat());

		//String issuer = cert.getIssuerX500Principal().toString();
		//System.out.println("Cert Issuer Name: " + issuer);

		System.out.println("\n");
	}

}

private static String get_content(HttpsURLConnection con) throws Exception {

	//System.out.println("****** Content of the URL ********"); 
	BufferedReader br =
		new BufferedReader(
				new InputStreamReader(con.getInputStream()));

	String input;
	String res = "";
	while ((input = br.readLine()) != null){
		res = res + input;      
		//System.out.println(input);
	}
	br.close();

	//System.out.println("\n");

	return res;
}

private void print_content(HttpsURLConnection con) throws Exception {

	//System.out.println("****** Content of the URL ********"); 
	BufferedReader br =
		new BufferedReader(
				new InputStreamReader(con.getInputStream()));

	String input;
	//String res = "";
	while ((input = br.readLine()) != null){
		//res = res + input;      
		System.out.println(input);
	}
	br.close();

	System.out.println("\n");

	//return res;
}

}

