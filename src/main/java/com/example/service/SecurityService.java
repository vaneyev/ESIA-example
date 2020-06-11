package com.example.service;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class SecurityService {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static boolean verifyJavaSecurity(final String data, final String sign, final X509Certificate cer,
			final String signatureAlgorithm) {
		try {
			Signature sig = Signature.getInstance(signatureAlgorithm);
			sig.initVerify(cer);
			sig.update(data.getBytes());
			return sig.verify(Base64.getUrlDecoder().decode(sign));
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return false;
	}

	public static boolean verifyBouncyCastle(String data, String sign, X509Certificate cer) {
		try {

			CMSProcessable signedContent = new CMSProcessableByteArray(data.getBytes());
			CMSSignedData signedData = new CMSSignedData(signedContent, Base64.getUrlDecoder().decode(sign));

			SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();

			boolean checkResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cer));
			return checkResult;

		} catch (CMSSignerDigestMismatchException ex) {
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return false;
	}

	public static byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey) {
		try {
			byte[] signedMessage = null;
			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData cmsData = new CMSProcessableByteArray(data);
			certList.add(signingCertificate);
			Store<?> certs = new JcaCertStore(certList);
			CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
			ContentSigner contentSigner = new JcaContentSignerBuilder(findSignatureAlgorithmName(signingCertificate))
					.build(signingKey);
			cmsGenerator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
							.build(contentSigner, signingCertificate));
			cmsGenerator.addCertificates(certs);
			CMSSignedData cms = cmsGenerator.generate(cmsData, true);
			signedMessage = cms.getEncoded();
			return signedMessage;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return new byte[0];
	}

	public static String findSignatureAlgorithmName(final X509Certificate signingCertificate)
			throws CertificateEncodingException, IOException {
		X509CertificateHolder certificateHolder = new X509CertificateHolder(signingCertificate.getEncoded());
		DefaultAlgorithmNameFinder af = new DefaultAlgorithmNameFinder();
		return af.getAlgorithmName(certificateHolder.getSignatureAlgorithm());
	}

}
