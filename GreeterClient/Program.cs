using System;
using CertificateUtil;
using Grpc.Core;
using Helloworld;

namespace GreeterClient
{
	internal class Program
	{
		public static void Main(string[] args)
		{
			if (args.Length != 2)
			{
				Console.WriteLine("Usage:");
				Console.WriteLine("<hostname> <port>");
				return;
			}

			var host = args[0];
			var port = Convert.ToInt32(args[1]);

			var rootCertificatesAsPem =
				CertificateUtils.GetUserRootCertificatesInPemFormat();

			var credentials = new SslCredentials(rootCertificatesAsPem);

			var channel = new Channel(host, port, credentials);

			var client = new Greeter.GreeterClient(channel);
			var user = Environment.UserName;

			var reply = client.SayHello(new HelloRequest {Name = user});
			Console.WriteLine("Greeting: " + reply.Message);

			channel.ShutdownAsync().Wait();
			Console.WriteLine("Press any key to exit...");
			Console.ReadKey();
		}
	}
}