# grpc-secure-greeter
Test SSL/TLS with the grpc/csharp hello world example using certificates from the Windows certificate store.

## Build and Run

Build and run the server:

```
> cd GreeterServer
> dotnet run -f netcoreapp3.1 <hostname> <port> <Thumbprint of server certificate>
```

Build and run the client:

```
> cd GreeterClient
> dotnet run -f netcoreapp3.1 <hostname> <port>
```

## Publish as Windows x64 Executable:

Build and run the server:

```
> cd GreeterServer
> dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true --self-contained true
```

Build and run the client:

```
> cd GreeterClient
> dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true --self-contained true
```

## 