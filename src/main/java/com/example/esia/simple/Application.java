package com.example.esia.simple;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.service.SecurityService;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootApplication
@RestController
public class Application extends SpringBootServletInitializer {
	@Value("${esia.authurl}")
	private String authurl;
	@Value("${esia.signatureAlgorithm}")
	private String signatureAlgorithm;
	@Value("${esia.clientId}")
	private String clientId;
	@Value("${esia.esiaCerPath}")
	private String esiaCerPath;
	@Value("${esia.keyStorePath}")
	private String keyStorePath;
	@Value("${esia.redirectUri}")
	private String redirectUri;
	@Value("${esia.resturl}")
	private String resturl;
	@Value("${esia.scope}")
	private String scope;
	@Value("${esia.tokenurl}")
	private String tokenurl;

	private X509Certificate esiaCertificate;
	private X509Certificate certificate;
	private PrivateKey privateKey;

	private String state = "";
	private String timeStamp;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String home() {
		loadCertificates(esiaCerPath, keyStorePath);
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
			sb.append("<h1>Информация о пользователе</h1><h2>Идентификатор</h2> ");
			sb.append(payload.getProperties().get("urn:esia:sbj_id"));
			sb.append("<h2>ФИО</h2> ");
			sb.append(esiaPerson.getProperties().get("lastName"));
			sb.append(" ");
			sb.append(esiaPerson.getProperties().get("firstName"));
			sb.append(" ");
			sb.append(esiaPerson.getProperties().get("middleName"));
			sb.append("<h2>Подпись ЕСИА</h2>");
			sb.append(verify(tokenArray[0] + "." + tokenArray[1], tokenArray[2]) ? "подтверждена" : "не подтверждена");
			sb.append("<h2>Авторизационный код</h2>");
			sb.append(new String(Base64.getUrlDecoder().decode(code.split("[.]")[1])));
			sb.append("<h2>Маркер идентификации</h2>");
			sb.append(new String(Base64.getUrlDecoder()
					.decode(authResponse.getProperties().get("id_token").toString().split("[.]")[1])));
			sb.append("<h2>Маркер доступа</h2>");
			sb.append(new String(Base64.getUrlDecoder()
					.decode(authResponse.getProperties().get("access_token").toString().split("[.]")[1])));
			sb.append("<h2>Маркер обновления</h2>");
			sb.append(authResponse.getProperties().get("refresh_token").toString());

			if (!SecurityService.verifyJavaSecurity(tokenArray[0] + "." + tokenArray[1], tokenArray[2], esiaCertificate,
					"SHA256withRSA"))
				sb.append("<h2>Верификация не пройдена</h2>");
			return sb.toString();

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return "";
	}

	private void loadCertificates(String esiaCerPath, String keyStorePath) {
		try {

			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			try (FileInputStream fis = new FileInputStream(esiaCerPath)) {
				esiaCertificate = (X509Certificate) fact.generateCertificate(fis);
			}

			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try (FileInputStream fis = new FileInputStream(keyStorePath)) {
				keyStore.load(fis, "".toCharArray());
				certificate = (X509Certificate) keyStore.getCertificate("esia");
				privateKey = (PrivateKey) keyStore.getKey("esia", "".toCharArray());
			}

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public String sign(String input) throws IOException {
		return Base64.getUrlEncoder().encodeToString(
				SecurityService.signData(input.getBytes("UTF-8"), certificate, privateKey));
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
