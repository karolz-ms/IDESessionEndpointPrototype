using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using VsSessionServer;
using System.IO;
using System;

var builder = WebApplication.CreateSlimBuilder(args);

var (publicCertFilePath, privateCertFilePath, certPassword) = CertGenerator.GenerateCertFiles();

try {
    Console.WriteLine($"Public cert file path  $env:DEBUG_SESSION_SERVER_CERT_FILE=\"{publicCertFilePath}\"");
    Console.WriteLine($"Private cert file path: {privateCertFilePath}");

    builder.WebHost.ConfigureKestrel(kestrelOptions =>
    {
        kestrelOptions.ListenLocalhost(5213, listenOptions => {
            listenOptions.UseHttps(privateCertFilePath, certPassword);
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
}
finally
{
    File.Delete(publicCertFilePath);
    File.Delete(privateCertFilePath);
}


