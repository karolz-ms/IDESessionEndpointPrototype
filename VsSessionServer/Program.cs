using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using VsSessionServer;
using System;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateSlimBuilder(args);

using var cert = CertGenerator.GenerateCert();
var certBytes = cert.Export(X509ContentType.Cert);
var certEncodedBytes = Convert.ToBase64String(certBytes);

Console.WriteLine($"Before running the client set  $env:DEBUG_SESSION_SERVER_CERT=\"{certEncodedBytes}\"");

builder.WebHost.ConfigureKestrel(kestrelOptions =>
{
    kestrelOptions.ListenLocalhost(5213, listenOptions => {
        listenOptions.UseHttps(cert);
    });
});

var app = builder.Build();
var sessionServer = new Server();

app.MapGet("/", () => "Visual Studio run session server");

var runSessionApi = app.MapGroup("/run_session");

runSessionApi.MapPut("/", sessionServer.SessionPut);

runSessionApi.Map("/notify", sessionServer.SessionNotify);

app.UseWebSockets();

app.Run();
