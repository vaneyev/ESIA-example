package com.example.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
@RestController
public class Application {
	private String cerPath = "D:\\data\\projects\\root.pem";
	private String keyPath = "D:\\data\\projects\\priv.pem";
	private String esiaCerPath = "D:\\data\\projects\\RSA_TESIA.cer";
	private String authurl = "https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac?";
	private String tokenurl = "https://esia-portal1.test.gosuslugi.ru/aas/oauth2/te";
	private String resturl = "https://esia-portal1.test.gosuslugi.ru/rs/prns/";
	private String clientId = "RPGUGP";
	private String redirectUri = "http://localhost:8080/info";
	private String scope = "openid fullname";
	private String state = "";
	private String timeStamp;
	private boolean useOpenSSL = false;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		try {
			Map<String, String> params = new LinkedHashMap<>();
			params.put("client_id", clientId);
			params.put("response_type", "code");
			params.put("redirect_uri", redirectUri);
			params.put("scope", scope);
			state = UUID.randomUUID().toString();
			params.put("state", state);
			params.put("access_type", "offline");
			DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss Z");
			timeStamp = dateFormat.format(new Date());
			params.put("timestamp", timeStamp);
			params.put("client_secret", sign(scope + timeStamp + clientId + state));

			return "<h1>ЕСИА</h1><a href=\"" + authurl + getParamsString(params) + "\">Вход</a>";

		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return "";
	}

	@RequestMapping("/info")
	public String info(@RequestParam("code") String code, @RequestParam("state") String state) {
		try {
			Map<String, String> params = new LinkedHashMap<>();
			params.put("client_id", clientId);
			params.put("code", code);
			params.put("grant_type", "authorization_code");
			params.put("redirect_uri", redirectUri);
			params.put("scope", scope);
			this.state = UUID.randomUUID().toString();
			params.put("state", this.state);
			DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss Z");
			timeStamp = dateFormat.format(new Date());
			params.put("timestamp", timeStamp);
			params.put("token_type", "Bearer");
			params.put("client_secret", sign(scope + timeStamp + clientId + this.state));

			byte[] postData = getParamsString(params).getBytes("UTF-8");
			URL objURL = new URL(tokenurl);
			HttpURLConnection con = (HttpURLConnection) objURL.openConnection();
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			con.setRequestProperty("Content-Length", String.valueOf(postData.length));
			con.setUseCaches(false);
			con.setDoOutput(true);
			con.getOutputStream().write(postData);

			ObjectMapper mapper = new ObjectMapper();
			GenericJSON authResponse;
			try (InputStream is = con.getInputStream();) {
				authResponse = mapper.readValue(is, GenericJSON.class);
			}

			String[] tokenArray = authResponse.getProperties().get("access_token").toString().split("[.]");
			GenericJSON payload = mapper.readValue(Base64.getUrlDecoder().decode(tokenArray[1]), GenericJSON.class);

			objURL = new URL(resturl + payload.getProperties().get("urn:esia:sbj_id"));
			con = (HttpURLConnection) objURL.openConnection();
			con.setRequestMethod("GET");
			con.setRequestProperty("Authorization", "Bearer " + authResponse.getProperties().get("access_token"));
			con.setUseCaches(false);
			GenericJSON esiaPerson;
			try (InputStream is = con.getInputStream();) {
				esiaPerson = mapper.readValue(is, GenericJSON.class);
			}

			StringBuilder sb = new StringBuilder();
			sb.append("<h1>Информация о пользователе</h1><br> Идентификатор: ");
			sb.append(payload.getProperties().get("urn:esia:sbj_id"));
			sb.append("<br> ФИО: ");
			sb.append(esiaPerson.getProperties().get("firstName"));
			sb.append(" ");
			sb.append(esiaPerson.getProperties().get("middleName"));
			sb.append(" ");
			sb.append(esiaPerson.getProperties().get("lastName"));
			sb.append("<br> Подпись ЕСИА: ");
			sb.append(verify(tokenArray[0] + "." + tokenArray[1], tokenArray[2]) ? "подтверждена" : "не подтверждена");
			sb.append("<br>Идентификационный токен:<br>");
			sb.append(new String(Base64.getUrlDecoder()
					.decode(authResponse.getProperties().get("id_token").toString().split("[.]")[1])));

			return sb.toString();

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return "";
	}

	private String sign(String input) {
		if (useOpenSSL)
			return signOpenSSL(input);
		else
			return signBouncyCastle(input);
	}

	private String signBouncyCastle(String input) {
		try {
			String strPK = new String(Files.readAllBytes(Paths.get(keyPath)), "UTF-8")
					.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
					.replace("\n", "");
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(strPK));
			PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(spec);
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate cer;
			try (FileInputStream fis = new FileInputStream(cerPath)) {
				cer = (X509Certificate) fact.generateCertificate(fis);
			}
			return Base64.getUrlEncoder().encodeToString(signData(input.getBytes("UTF-8"), cer, pk));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return "";
	}

	private boolean verify(String data, String sign) {
		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			X509Certificate cer;
			try (FileInputStream fis = new FileInputStream(esiaCerPath)) {
				cer = (X509Certificate) fact.generateCertificate(fis);
			}
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(cer);
			sig.update(data.getBytes());
			return sig.verify(Base64.getUrlDecoder().decode(sign));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return false;

	}

	private String signOpenSSL(String input) {
		File inFile = null;
		File outFile = null;
		try {
			inFile = File.createTempFile("text", ".msg");
			Files.write(inFile.toPath(), input.getBytes(), StandardOpenOption.APPEND);
			outFile = File.createTempFile("sign", ".msg");
			StringBuilder sb = new StringBuilder();
			sb.append("openssl smime -sign -md sha256 -in ");
			sb.append(inFile.getAbsolutePath());
			sb.append(" -signer ");
			sb.append(cerPath);
			sb.append(" -inkey ");
			sb.append(keyPath);
			sb.append(" -out ");
			sb.append(outFile.getAbsolutePath());
			sb.append(" -outform DER");
			Process proc = Runtime.getRuntime().exec(sb.toString());
			proc.waitFor();
			return Base64.getUrlEncoder().encodeToString(Files.readAllBytes(outFile.toPath()));
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			if (inFile != null && inFile.exists())
				inFile.delete();
			if (outFile != null && outFile.exists())
				outFile.delete();
		}

		return "";
	}

	public static byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey) {
		try {
			byte[] signedMessage = null;
			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData cmsData = new CMSProcessableByteArray(data);
			certList.add(signingCertificate);
			Store<?> certs = new JcaCertStore(certList);
			CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
			ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner,
							signingCertificate));
			cmsGenerator.addCertificates(certs);
			CMSSignedData cms = cmsGenerator.generate(cmsData, true);
			signedMessage = cms.getEncoded();
			return signedMessage;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return new byte[0];

	}

	public static String getParamsString(Map<String, String> params) throws UnsupportedEncodingException {
		StringBuilder result = new StringBuilder();

		for (Map.Entry<String, String> entry : params.entrySet()) {
			result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
			result.append("=");
			result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
			result.append("&");
		}

		String resultString = result.toString();
		return resultString.length() > 0 ? resultString.substring(0, resultString.length() - 1) : resultString;
	}
}
