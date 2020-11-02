using System;
using System.CodeDom.Compiler;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace SpiralCheckoutTesting
{
    class Program
    {
        const String clientId = "000000000000001";
        const String clientPrivateKey = @"C:\Code\Spiral\www\spiraljs\01pri.xml";
        const String serverPublicKey = @"C:\Code\Spiral\www\spiraljs\01pub.xml";

        static void fromXmlString(RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                        case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                        case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                        case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                        case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                        case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                        case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        static String RSA_Sha256_Signature(String data, String fileName)
        {
            // Method 1: Convert pem file into p12 by using openssl and using the 2 lines code below
            // req -new -key PEMFile.pem -x509 -days 365 -out CRTFile.crt
            // pkcs12 –export –in CRTFile.crt –inkey PEMFile.pem –out P12File.p12
            // 
            //X509Certificate2 cert = new X509Certificate2(@"C:\Code\Spiral\www\spiraljs\P12File.p12", "1234");
            //RSA rsa = cert.GetRSAPrivateKey();

            // Method 2: Using XML format, there are online tool available to convert pem into xml format
            // e.g.: https://the-x.cn/en-us/certificate/PemToXml.aspx
            RSA rsa = RSA.Create();
            // rsa.FromXmlString(File.ReadAllText(fileName));
            fromXmlString(rsa, File.ReadAllText(fileName));

            ASCIIEncoding encoder = new ASCIIEncoding();
            byte[] binData = encoder.GetBytes(data);
            byte[] binSignature = rsa.SignData(binData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(binSignature);
        }

        static bool RSA_Sha256_Verify(String data, String signature, String fileName)
        {
            // Method 1: Using P12 file. Generate it or convert from pem file (see below) by using openssl
            // req -new -key PEMFile.pem -x509 -days 365 -out CRTFile.crt
            // pkcs12 –export –in CRTFile.crt –inkey PEMFile.pem –out P12File.p12
            // 
            //X509Certificate2 cert = new X509Certificate2(@"C:\Code\Spiral\www\spiraljs\P12File.p12", "1234");
            //RSA rsa = cert.GetRSAPrivateKey();

            // Method 2: Using XML format, there are online tool available to convert pem into xml format
            // e.g.: https://the-x.cn/en-us/certificate/PemToXml.aspx
            RSA rsa = RSA.Create();
            //rsa.FromXmlString(File.ReadAllText(fileName));
            fromXmlString(rsa, File.ReadAllText(fileName));

            ASCIIEncoding encoder = new ASCIIEncoding();
            byte[] binData = encoder.GetBytes(data);
            byte[] binSignature = Convert.FromBase64String(signature);

            return rsa.VerifyData(binData, binSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        static async System.Threading.Tasks.Task<string> webAPIRequestAsync()
        {
            // Set time and merchant ref
            DateTime dt = DateTime.Now;
            DateTime utcTime = dt.ToUniversalTime();

            String timeString = string.Format("{0}Z", utcTime.ToString("s"));
            Console.WriteLine("ISO Time: " + timeString);

            String merchantRef = utcTime.Ticks.ToString();
            Console.WriteLine("Merchant Ref: " + merchantRef);

            // construct the body
            var bodydata = new
            {
                clientId = clientId,
                cmd = "SALESESSION",
                type = "VM",
                amt = 0.1,
                merchantRef = merchantRef,
                channel = "WEB",
                successUrl = "https://www.google.com",
                failureUrl = "https://www.google.com",
                webhookUrl = "https://www.google.com",
                goodsName = "Testing Goods"
            };
            string body = JsonSerializer.Serialize(bodydata);
            Console.WriteLine("Body: " + body);

            // calculate header
            String signature = RSA_Sha256_Signature(clientId + merchantRef + timeString, clientPrivateKey);
            Console.WriteLine("Signature: " + signature);

            // construct HTTP client 
            HttpClient httpClient = new HttpClient();
            var requestMessage = new HttpRequestMessage(HttpMethod.Put, "https://cjpazdufok.execute-api.ap-east-1.amazonaws.com/v1/merchants/" + clientId + "/transactions/" + merchantRef);

            requestMessage.Headers.Clear();
            requestMessage.Headers.Add("Spiral-Request-Datetime", timeString);
            requestMessage.Headers.Add("Spiral-Client-Signature", signature);
            requestMessage.Content = new StringContent(body, Encoding.UTF8, "application/json");

            // send and receive
            HttpResponseMessage response = await httpClient.SendAsync(requestMessage);

            Console.WriteLine("Status code: " + response.StatusCode);

            // verify signature
            signature = response.Headers.GetValues("Spiral-Server-Signature").FirstOrDefault();
            String signData = clientId + merchantRef + response.Headers.GetValues("Spiral-Request-Datetime").FirstOrDefault();
            if (RSA_Sha256_Verify(signData, signature, serverPublicKey))
                Console.WriteLine("Server signature verified!");
            else
                Console.WriteLine("Server signature verification failed");

            string result = await response.Content.ReadAsStringAsync();

            return result;
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            // Generate Signature
            Console.WriteLine("Client ID: " + clientId);

            String response = webAPIRequestAsync().GetAwaiter().GetResult();

            Console.WriteLine("Response: " + response);

            Console.WriteLine("Bye World!");
        }
    }
}

