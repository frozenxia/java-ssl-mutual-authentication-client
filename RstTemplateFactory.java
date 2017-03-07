/**
 * @Title: RestTemplateFactory.java
 * @date:Mar 6, 2017 2:46:41 PM
 * @Description:TODO
 */
package com.xiaomi.ecaa.clients;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;


/**
 *
 * @Description resttemplate factory for self-signed certificate
 * @date Mar 6, 2017 2:46:41 PM
 *
 */
public class RstTemplateFactory {
	private String keyStrorePassword;
	private String keyStoreRecoverPassword;
	private String keyStorePath;

	private String trustStorePath;
	private String trustStorePassword;
	private static final Log logger = LogFactory.getLog(RstTemplateFactory.class.getName());

	public RstTemplateFactory() {

	}

	public RstTemplateFactory setKeyStorePassword(String keyStorePassword) {
		this.keyStoreRecoverPassword = keyStorePassword;
		return this;
	}

	public RstTemplateFactory setKeyStoreRecoverPassword(String keyStoreRecoverPassword) {
		this.keyStoreRecoverPassword = keyStoreRecoverPassword;
		return this;
	}

	public RstTemplateFactory setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
		return this;
	}

	public RstTemplateFactory setTrustStorePath(String trustStorePath) {
		this.trustStorePath = trustStorePath;
		return this;
	}

	public RstTemplateFactory setTrustStorePassword(String trustStorePassword) {
		this.trustStorePassword = trustStorePassword;
		return this;
	}

	public RestTemplate build() {
		try {
			RestTemplate template = initRestTemplate();
			return template;
		} catch (Exception e) {
			logger.error("get template error ", e);
		}
		return null;
	}

	private RestTemplate initRestTemplate() throws UnrecoverableKeyException, KeyManagementException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		ClientHttpRequestFactory requestFactory = this.initRequestFactory();
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.setRequestFactory(requestFactory);
		return restTemplate;
	}

	private ClientHttpRequestFactory initRequestFactory() throws UnrecoverableKeyException, KeyManagementException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		HttpClient httpClient = this.initHttpClient();
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		requestFactory.setConnectionRequestTimeout(10000);// 10seconds
		requestFactory.setReadTimeout(60000);// 60 seconds
		return requestFactory;
	}

	private KeyManager[] initKeyManager() throws NoSuchAlgorithmException, KeyStoreException, CertificateException,
			IOException, UnrecoverableKeyException {
		String clientKeyStorePath = keyStorePath;
		String clientKeyStorePassword = keyStrorePassword;
		String clientKeyStoreRecoverPassword = keyStoreRecoverPassword;

		File keyStoreFile = new File(clientKeyStorePath);
		if (!keyStoreFile.exists()) {
			throw new FileNotFoundException("keyStore file not found" + keyStoreFile.getAbsolutePath());
		}

		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		KeyStore tks = KeyStore.getInstance("JKS");
		tks.load(new FileInputStream(keyStoreFile), clientKeyStorePassword.toCharArray());
		kmf.init(tks, clientKeyStoreRecoverPassword.toCharArray());
		return kmf.getKeyManagers();
	}

	private TrustManager[] initTrustManager()
			throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		String trustKeyStorePath = this.trustStorePath;
		String trustKeyStorePassword = this.trustStorePassword;

		File trustKeyStoreFile = new File(trustKeyStorePath);
		if (!trustKeyStoreFile.exists()) {
			throw new FileNotFoundException("trustKeyStore file not found, " + trustKeyStoreFile.getAbsolutePath());
		}

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		KeyStore tks = KeyStore.getInstance("JKS");
		tks.load(new FileInputStream(trustKeyStoreFile), trustKeyStorePassword.toCharArray());
		tmf.init(tks);
		return tmf.getTrustManagers();
	}

	private HttpClientBuilder initHttpClientBuilder() throws UnrecoverableKeyException, KeyManagementException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		PoolingHttpClientConnectionManager poolingClientManager = this.initPoolingConnectionManager();
		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		httpClientBuilder.setConnectionManager(poolingClientManager);
		httpClientBuilder.setRetryHandler(new DefaultHttpRequestRetryHandler(2, true));
		httpClientBuilder.setKeepAliveStrategy(DefaultConnectionKeepAliveStrategy.INSTANCE);
		return httpClientBuilder;
	}

	private HttpClient initHttpClient() throws UnrecoverableKeyException, KeyManagementException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		HttpClientBuilder builder = this.initHttpClientBuilder();
		HttpClient httpClient = builder.build();
		return httpClient;
	}

	private PoolingHttpClientConnectionManager initPoolingConnectionManager() throws UnrecoverableKeyException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, KeyManagementException {
		KeyManager[] kms = this.initKeyManager();
		TrustManager[] tms = this.initTrustManager();
		SSLContext sslContext = this.initSSLContext(kms, tms);

		SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslContext);
		Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("https", sslConnectionSocketFactory).build();
		PoolingHttpClientConnectionManager poolingConnectionManager = new PoolingHttpClientConnectionManager(
				socketFactoryRegistry);
		poolingConnectionManager.setMaxTotal(5);
		poolingConnectionManager.setDefaultMaxPerRoute(5);
		return poolingConnectionManager;
	}

	private SSLContext initSSLContext(KeyManager[] km, TrustManager[] tm)
			throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(km, tm, null);
		return sslContext;
	}
}
