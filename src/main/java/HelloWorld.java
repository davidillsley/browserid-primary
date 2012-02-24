import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.i5y.json.stream.JSONEvent;
import org.i5y.json.stream.JSONTypeSafeWriters.InsideObject;
import org.i5y.json.stream.JSONTypeSafeWriters.ObjectWriter;
import org.i5y.json.stream.impl.JSONParserImpl;
import org.i5y.json.stream.impl.JSONStreamFactoryImpl;

public class HelloWorld {

	private static BigInteger n;
	private static BigInteger e;
	private static PrivateKey privateKey;

	public static class PublicServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			resp.setContentType("application/json");
			resp.addHeader("Cache-Control", "no-store, max-age=0");
			new JSONStreamFactoryImpl().createObjectWriter(resp.getWriter())
					.startObject().defineProperty("public-key").startObject()
					.defineProperty("algorithm").literal("RS")
					.defineProperty("n").literal(n.toString())
					.defineProperty("e").literal(e.toString()).endObject()
					.defineProperty("authentication")
					.literal("/browserid/signin.html")
					.defineProperty("provisioning")
					.literal("/browserid/provision.html").endObject().close();
		}
	}

	public static class SignServlet extends HttpServlet {
		@Override
		protected void doPost(HttpServletRequest req, HttpServletResponse resp)
				throws ServletException, IOException {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int next = req.getInputStream().read();
			while (next >= 0) {
				baos.write(next);
				next = req.getInputStream().read();
			}
			System.out.println("sign: " + new String(baos.toByteArray()));
			resp.setContentType("application/json");
			JSONParserImpl jpi = new JSONParserImpl(new String(
					baos.toByteArray()));
			while (jpi.next() != JSONEvent.PROPERTY_NAME
					&& !"pubkey".equals(jpi.string()))
				;
			Map<String, String> details = new HashMap<String, String>();
			while (jpi.next() != JSONEvent.OBJECT_END) {
				if (jpi.current() == JSONEvent.PROPERTY_NAME) {
					String propertyName = jpi.string();
					jpi.advance();
					String propertyValue = jpi.string();
					details.put(propertyName, propertyValue);
				}
			}
			ByteArrayOutputStream baoss = new ByteArrayOutputStream();
			ObjectWriter objectWriter = new JSONStreamFactoryImpl()
					.createObjectWriter(new OutputStreamWriter(baoss));
			InsideObject<InsideObject<ObjectWriter>> readyForCert = objectWriter
					.startObject().defineProperty("iss")
					.literal("browserid-i5y.herokuapp.com")
					.defineProperty("exp")
					.literal(System.currentTimeMillis() + 1000 * 60 * 60)
					.defineProperty("iat").literal(System.currentTimeMillis())
					.defineProperty("public-key").startObject();
			for (Entry<String, String> entry : details.entrySet()) {
				readyForCert = readyForCert.defineProperty(entry.getKey())
						.literal(entry.getValue());
			}
			readyForCert.endObject().defineProperty("principal").startObject()
					.defineProperty("email")
					.literal("test@browserid-i5y.herokuapp.com").endObject()
					.endObject().close();
			String header = encodeURLBase64("{\"alg\":\"RS256\"}");
			String body = encodeURLBase64(new String(baoss.toByteArray()));
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
			new JSONStreamFactoryImpl().createObjectWriter(resp.getWriter())
					.startObject().defineProperty("certificate")
					.literal(total + "." + signature).endObject().close();
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
		Server server = new Server(Integer.valueOf(System.getenv("PORT")));
		ServletContextHandler context = new ServletContextHandler(
				ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		context.addServlet(new ServletHolder(new PublicServlet()),
				"/.well-known/browserid");
		context.addServlet(new ServletHolder(new SignServlet()),
				"/browserid/sign");

		ResourceHandler resource_handler = new ResourceHandler();
		resource_handler.setDirectoriesListed(false);
		resource_handler.setWelcomeFiles(new String[] { "index.html" });

		resource_handler.setResourceBase("target/classes");

		HandlerList handlers = new HandlerList();
		handlers.setHandlers(new Handler[] { resource_handler, context });
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
