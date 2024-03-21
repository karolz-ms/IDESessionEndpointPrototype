﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VsSessionServer;

public static class CertGenerator
{
    public static (string publicCertFilePath, string privateCertFilePath, string certPassword) GenerateCertFiles()
    {
        const int rsaKeySize = 2048;
        var rsa = RSA.Create(rsaKeySize); // Create asymmetric RSA key pair.
        var req = new CertificateRequest(
            "cn=debug-session.visualstudio.microsoft.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );

        var sanbuilder = new SubjectAlternativeNameBuilder();
        sanbuilder.AddDnsName("localhost");
        req.CertificateExtensions.Add(sanbuilder.Build());

        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddSeconds(-5),
            DateTimeOffset.UtcNow.AddDays(7)
        );

        string randomFileName()
        {
            return PasswordGenerator.Generate(24, true, true, true, false, 0, 0, 0, 0);
        }

        byte[] publicKeyCertData = cert.Export(X509ContentType.Cert);
        var publicCertFilePath = Path.Combine(Path.GetTempPath(), $"{randomFileName()}.cer");
        File.WriteAllBytes(publicCertFilePath, publicKeyCertData);

        string certPassword = PasswordGenerator.Generate(24, true, true, true, true, 0, 0, 0, 0);
        byte[] privateKeyCertData = cert.Export(X509ContentType.Pfx, certPassword);
        var privateCertFilePath = Path.Combine(Path.GetTempPath(), $"{randomFileName()}.pfx");
        File.WriteAllBytes(privateCertFilePath, privateKeyCertData);
        return (publicCertFilePath, privateCertFilePath, certPassword);
    }
}