using System;
using System.Security.Cryptography.X509Certificates;
using CertificateUtil;
using Grpc.Core;
using Helloworld;

namespace GreeterClient
{
	internal class Program
	{
		private const string InsecureArg = "INSECURE";

		public static void Main(string[] args)
		{
			if (args.Length < 2)
			{
				Console.WriteLine("Usage:");
				Console.WriteLine("<hostname> <port> {Thumbprint of client certificate}");
				Console.WriteLine();
				Console.WriteLine("Usage for insecure communication:");
				Console.WriteLine($"<hostname> <port> {InsecureArg}");
				return;
			}

			var host = args[0];
			var port = Convert.ToInt32(args[1]);

			string clientCertificate = null;
			if (args.Length == 3)
			{
				clientCertificate = args[2];
			}

			ChannelCredentials credentials;
			
			if (clientCertificate != null &&
			    clientCertificate.Equals(InsecureArg, StringComparison.InvariantCultureIgnoreCase))
			{
				credentials = ChannelCredentials.Insecure;
			}
			else
			{
				credentials = GetSslCredentials(clientCertificate);
			}

			var channel = new Channel(host, port, credentials);

			var client = new Greeter.GreeterClient(channel);
			var user = Environment.UserName;

			var reply = client.SayHello(new HelloRequest {Name = user});
			Console.WriteLine("Greeting: " + reply.Message);

			channel.ShutdownAsync().Wait();
			Console.WriteLine("Press any key to exit...");
			Console.ReadKey();
		}

		private static SslCredentials GetSslCredentials(string clientCertificate)
		{
			var rootCertificatesAsPem =
				CertificateUtils.GetUserRootCertificatesInPemFormat();

			KeyCertificatePair sslClientCertificate = null;
			if (clientCertificate != null)
			{
				sslClientCertificate = GetClientCertificate(clientCertificate);
			}

			var credentials = new SslCredentials(rootCertificatesAsPem, sslClientCertificate);
			return credentials;
		}

		private static KeyCertificatePair GetClientCertificate(string thumbPrint)
		{
			KeyCertificatePair sslClientCertificate;
			var keyPair = CertificateUtils.FindKeyCertificatePairFromStore(
				thumbPrint, new[]
				{
					X509FindType.FindByThumbprint
				}, StoreName.My, StoreLocation.CurrentUser);

			if (keyPair != null)
			{
				Console.WriteLine("Using client-side certificate");

				sslClientCertificate =
					new KeyCertificatePair(keyPair.PublicKey, keyPair.PrivateKey);
			}
			else
			{
				throw new ArgumentException(
					$"Could not usable find client certificate {thumbPrint} in certificate store.");
			}

			return sslClientCertificate;
		}
	}
}