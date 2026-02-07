import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.NoSuchAlgorithmException;

public class HttpsPing {

    public static void main(String[] args) {
        String targetUrl = "https://www.google.com";

        try {
            System.out.println("Connecting to " + targetUrl + "...");
            URL url = new URL(targetUrl);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Connect
            connection.connect();

            // Get Cipher Suite
            String cipherSuite = connection.getCipherSuite();
            System.out.println("Response Code: " + connection.getResponseCode());
            System.out.println("Cipher Suite: " + cipherSuite);

            // Print Protocol Version
            try {
                SSLContext context = SSLContext.getDefault();
                System.out.println("SSL Protocol: " + context.getProtocol());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            connection.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
