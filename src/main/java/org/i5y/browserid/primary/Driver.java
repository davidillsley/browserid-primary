package org.i5y.browserid.primary;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.json.JsonBuilder;
import javax.json.JsonBuilder.JsonBuildable;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.json.stream.JsonGenerator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.mindrot.jbcrypt.BCrypt;

public class Driver {

	private static BigInteger n;
	private static BigInteger e;
	private static PrivateKey privateKey;

	private static ConcurrentMap<String, String> emailToPasswordHashes;

	public static class PublicServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			resp.setContentType("application/json");
			resp.addHeader("Cache-Control", "no-store, max-age=0");
			new JsonGenerator(resp.getWriter()).beginObject()
					.beginObject("public-key").add("algorithm", "RS")
					.add("n", n.toString()).add("e", e.toString()).endObject()
					.add("authentication", "/")
					.add("provisioning", "/provision").endObject().close();
		}
	}

	public static class ProvisionServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			resp.setStatus(200);
			resp.setContentType("text/html");
			if ("true".equals(req.getSession().getAttribute("authenticated"))) {
				req.getRequestDispatcher("/provision.html").include(req, resp);
			} else {
				req.getRequestDispatcher("/provisionfail.html").include(req,
						resp);
			}
		}
	}

	public static class SignInServlet extends HttpServlet {
		@Override
		protected void doPost(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			String email = req.getParameter("email");
			String password = req.getParameter("password");

			System.out.println("Signing in... " + email);
			resp.setContentType("application/json");
			boolean success = false;
			String errorMessage = "";
			String passwordHash = emailToPasswordHashes
					.get(email.toLowerCase());
			if (passwordHash == null) {
				errorMessage = "email not recognised";
			} else if (BCrypt.checkpw(password, passwordHash)) {
				req.getSession().setAttribute("authenticated", "true");
				req.getSession().setAttribute("email", email);
				success = true;
			} else {
				System.out.println("password: " + password + " hash: "
						+ passwordHash);
				errorMessage = "incorrect password";
			}
			new JsonGenerator(resp.getWriter()).beginObject()
					.add("success", success).add("message", errorMessage)
					.endObject().close();
		}
	}

	public static class SignServlet extends HttpServlet {
		@Override
		protected void doPost(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			if ("true".equals(req.getSession().getAttribute("authenticated"))) {
				String email = (String) req.getSession().getAttribute("email");
				resp.setContentType("application/json");

				JsonObject wholeBody = (JsonObject) new JsonReader(
						req.getReader()).readObject();
				System.out.println("sign: " + wholeBody);

				JsonObject pubkey = wholeBody.getValue("pubkey",
						JsonObject.class);

				JsonObjectBuilder<JsonBuildable<JsonObject>> beginObject = new JsonBuilder()
						.beginObject();
				beginObject
						.add("iss", email.split("@")[1])
						.add("exp", System.currentTimeMillis() + 1000 * 60 * 60)
						.add("iat", System.currentTimeMillis());

				beginObject.add("public-key", pubkey);

				beginObject.beginObject("principal").add("email", email)
						.endObject();

				JsonObject obj = beginObject.endObject().build();

				StringWriter sw = new StringWriter();
				JsonWriter writer = new JsonWriter(sw);
				writer.writeObject(obj);
				writer.close();

				String header = encodeURLBase64("{\"alg\":\"RS256\"}");
				String body = encodeURLBase64(sw.toString());
				String total = header + "." + body;
				String signature;
				try {
					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initSign(privateKey);
					sig.update(total.getBytes());
					byte[] sign = sig.sign();
					signature = encodeURLBase64(sign);
				} catch (Exception e) {
					e.printStackTrace();
					throw new IOException(e);
				}
				System.out.println("signed: " + total + "." + signature);
				new JsonGenerator(resp.getWriter()).beginObject()
						.add("certificate", total + "." + signature)
						.endObject().close();
			} else {
				// Fail hard...
			}
		}
	}

	private static String encodeURLBase64(byte[] input) {
		String encoded = new String(Base64.encode(input));
		return encoded.replace('+', '-').replace('/', '_').replace("=", "");
	}

	private static String encodeURLBase64(String input) {
		return encodeURLBase64(input.getBytes());
	}

	public static void main(String[] args) throws Exception {
		String customConfigfile = System.getenv("BROWSERID_CONFIG");
		final File configFile;
		if (customConfigfile != null) {
			configFile = new File(customConfigfile);
		} else {
			configFile = new File(System.getProperty("user.home"),
					".browseridprimary.properties");
		}
		Properties config = new Properties();
		config.load(new FileInputStream(configFile));
		int port = Integer.valueOf(config.getProperty("port", "5000"));
		Server server = new Server(port);

		emailToPasswordHashes = new ConcurrentHashMap<String, String>();

		for (Entry<Object, Object> entry : config.entrySet()) {
			String key = (String) entry.getKey();
			if (key.startsWith("email.")) {
				String email = key.substring(6).toLowerCase();
				String value = (String) entry.getValue();
				String passwordHash = new String(Base64.decode(value));
				emailToPasswordHashes.put(email, passwordHash);
				System.out.println("email supported: " + email);
			}
		}

		ServletContextHandler context = new ServletContextHandler(
				ServletContextHandler.SESSIONS);
		context.setContextPath("/");

		context.addServlet(new ServletHolder(new PublicServlet()),
				"/.well-known/browserid");
		context.addServlet(new ServletHolder(new SignServlet()), "/sign");
		context.addServlet(new ServletHolder(new SignInServlet()), "/signin");
		context.addServlet(new ServletHolder(new ProvisionServlet()),
				"/provision");

		ServletHolder defaultServletHolder = new ServletHolder(
				new DefaultServlet());
		defaultServletHolder.setInitParameter("resourceBase", "target/classes");
		context.addServlet(defaultServletHolder, "/");

		HandlerList handlers = new HandlerList();
		handlers.setHandlers(new Handler[] { context });
		server.setHandler(handlers);

		// Init public/private key...
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		privateKey = keyPair.getPrivate();
		n = publicKey.getModulus();
		e = publicKey.getPublicExponent();
		System.out.println(n);
		System.out.println(e);
		server.start();
		server.join();
	}
}
