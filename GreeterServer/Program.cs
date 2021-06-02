using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateUtil;
using Grpc.Core;
using Helloworld;

namespace GreeterServer
{
	internal class GreeterImpl : Greeter.GreeterBase
	{
		// Server side handler of the SayHello RPC
		public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context)
		{
			Console.WriteLine("Oh, we've got mail!");
			return Task.FromResult(new HelloReply {Message = "Hello " + request.Name});
		}
	}

	internal class Program
	{
		private const string InsecureArg = "INSECURE";

		public static void Main(string[] args)
		{
			if (args.Length < 3)
			{
				PrintUsage();
				return;
			}

			// NOTE: Localhost won't work if the SAN in the certificate is <machine name>.<domain name>.com
			var host = args[0];
			var port = Convert.ToInt32(args[1]);
			var certificate = args[2];

			ServerCredentials serverCredentials;

			if (certificate.Equals("INSECURE", StringComparison.InvariantCultureIgnoreCase))
			{
				serverCredentials = ServerCredentials.Insecure;
			}
			else if (File.Exists(certificate))
			{
				Console.WriteLine("Using certificate from files... ");

				if (args.Length < 4)
				{
					Console.WriteLine("No private key file specified.");
					PrintUsage();
				}

				string privateKeyFile = args[3];

				serverCredentials = GetServerCredentials(certificate, privateKeyFile);
			}
			else
			{
				Console.WriteLine("Getting certificate from certificate store... ");

				bool enforceMutualTls =
					args.Length == 4
					&& args[3].Equals("--request_client_cert", StringComparison.InvariantCultureIgnoreCase);

				serverCredentials = GetServerCredentials(certificate, enforceMutualTls);
			}

			var server = new Server
			{
				Services = {Greeter.BindService(new GreeterImpl())},
				Ports = {new ServerPort(host, port, serverCredentials)}
			};
			server.Start();

			Console.WriteLine("Greeter server listening on port " + port);
			Console.WriteLine("Press any key to stop the server...");
			Console.ReadKey();

			server.ShutdownAsync().Wait();
		}

		/// <summary>
		/// Creates the server credentials using two PEM files.
		/// </summary>
		/// <param name="certificateFile"></param>
		/// <param name="privateKeyFile"></param>
		/// <returns></returns>
		private static ServerCredentials GetServerCredentials(string certificateFile, 
			string privateKeyFile)
		{
			var keyPair = new KeyPair(File.ReadAllText(privateKeyFile),
				File.ReadAllText(certificateFile));

			return GetServerCredentials(keyPair, false);
		}


		/// <summary>
		/// Creates the server credentials using a certificate from the Certificate Store.
		/// </summary>
		/// <param name="certificate">
		///     The certificate store's certificate (subject or thumbprint)
		///     or the PEM file containing the certificate chain.
		/// </param>
		/// <param name="enforceMutualTls">Enforce client authentication.</param>
		/// <returns></returns>
		private static ServerCredentials GetServerCredentials(
			string certificate,
			bool enforceMutualTls = false)
		{
			if (string.IsNullOrEmpty(certificate))
			{
				Console.WriteLine("Certificate was not provided. Using insecure credentials.");

				return ServerCredentials.Insecure;
			}

			var certificateKeyPair =
				TryGetServerCertificateKeyPair(certificate);

			if (certificateKeyPair == null)
			{
				return ServerCredentials.Insecure;
			}

			return GetServerCredentials(certificateKeyPair, enforceMutualTls);
		}

		private static ServerCredentials GetServerCredentials(KeyPair certificateKeyPair, bool enforceMutualTls)
		{
			var keyCertificatePairs =
				new List<KeyCertificatePair>
				{
					new KeyCertificatePair(
						certificateKeyPair.PublicKey, certificateKeyPair.PrivateKey)
				};

			var rootCertificatesAsPem =
				CertificateUtils.GetUserRootCertificatesInPemFormat();

			// If not required, still verify the client certificate, if presented
			var clientCertificates =
				enforceMutualTls
					? SslClientCertificateRequestType.RequestAndRequireAndVerify
					: SslClientCertificateRequestType.DontRequest;

			ServerCredentials result = new SslServerCredentials(
				keyCertificatePairs, rootCertificatesAsPem,
				clientCertificates);

			return result;
		}


		private static KeyPair TryGetServerCertificateKeyPair(
			string certificate)
		{
			// Find server certificate from Store (Local Computer, Personal folder)
			var result = CertificateUtils.FindKeyCertificatePairFromStore(
				certificate,
				new[]
				{
					X509FindType.FindByThumbprint
				}, StoreName.My, StoreLocation.LocalMachine);

			if (result == null)
				Console.WriteLine(
					"No certificate could be found by '{0}'. Using insecure credentials (no TLS).",
					certificate);
			else
				Console.WriteLine("Using certificate from certificate store for TLS.");

			return result;
		}

		private static void PrintUsage()
		{
			Console.WriteLine("Usage:");
			Console.WriteLine("<hostname> <port> <Thumbprint of server certificate> {--request_client_cert}");
			Console.WriteLine("<hostname> <port> <Certificate (public key) as PEM file> <Private key PEM file>");
			Console.WriteLine();
			Console.WriteLine("Usage for insecure communication:");
			Console.WriteLine($"<hostname> <port> {InsecureArg}");
		}
	}
}