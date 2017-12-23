﻿using CommandLine;
using DokanNet;
using Renci.SshNet;
using Renci.SshNet.Common;
using Sshfs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SSHFS.CLI
{
    class Options
    {
        // Paths
        [Option('d', "drive-letter",
            Required = true,
            HelpText = "Drive letter to mount the remote SFTP path under")]
        public char DriveLetter { get; set; }
        [Option('r', "path",
            Required = true,
            HelpText = "Absolute path of directory to be mounted from remote system")]
        public string Path { get; set; }

        // Remote host
        [Option('h', "host",
            Required = true,
            HelpText = "IP or hostname of remote host")]
        public string Host { get; set; }
        [Option('p', "port",
            Required = false, DefaultValue = 22,
            HelpText = "SSH service port on remote server")]
        public int Port { get; set; }

        // Auth
        [Option('u', "username",
            Required = true,
            HelpText = "Name of SSH user on remote system")]
        public string Username { get; set; }
        [Option('x', "password",
            Required = false,
            HelpText = "INSECURE: SSH user's password, if password-based or keyboard-interactive auth should be attempted. Note that the security model for this is equivalent to sshpass's -p option, and exposes your password to any process on the machine that cares to run ps")]
        public string Password { get; set; }
        [OptionArray('k', "private-keys",
            Required = false,
            HelpText = "Path to SSH user's private key(s), if key-based auth should be attempted")]
        public string[] Keys { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            var options = new Options();
            Parser.Default.ParseArgumentsStrict(args, options);

            var auths = GetAuthMechanisms(options);

            var fs = auths
                .Select(auth => AttemptConnection(auth.Item1, auth.Item2, options.Path))
                .FirstOrDefault(result => result != null);

            if (fs == null)
                throw new InvalidOperationException("Could not connect to server with any known authentication mechanism");

            fs.Mount($"{options.DriveLetter}", new DokanNet.Logging.NullLogger());
        }

        static IEnumerable<(string, ConnectionInfo)> GetAuthMechanisms(Options options)
        {
            var auths = new List<(string, ConnectionInfo)>();

            if (options.Keys != null)
            {
                auths.AddRange(new(string, ConnectionInfo)[] {
                    ("private key", PrivateKeyConnectionInfo(options))
                });
            }

            if (options.Password != null)
            {
                auths.AddRange(new(string, ConnectionInfo)[] {
                    ("password", new PasswordConnectionInfo(options.Host, options.Port, options.Username, options.Password)),
                    ("keyboard-interactive", KeyboardInteractiveConnectionInfo(options))
                });
            }

            return auths;
        }

        static PrivateKeyConnectionInfo PrivateKeyConnectionInfo(Options options)
        {
            var pkFiles = options.Keys.Select(k =>
            {
                var match = Regex.Match(k, @"(?<keyfile>\S+)(:?\s+ (?<passphrase>\S+))?");
                var keyfile = match.Groups["keyfile"];
                var passphrase = match.Groups["passphrase"];

                return passphrase.Success ? new PrivateKeyFile(keyfile.Value, passphrase.Value) : new PrivateKeyFile(keyfile.Value);
            });

            return new PrivateKeyConnectionInfo(options.Host, options.Port, options.Username, pkFiles.ToArray());
        }

        static KeyboardInteractiveConnectionInfo KeyboardInteractiveConnectionInfo(Options options)
        {
            var auth = new KeyboardInteractiveConnectionInfo(options.Host, options.Port, options.Username);

            auth.AuthenticationPrompt += (sender, e) =>
            {
                var passPrompts = e.Prompts
                    .Where(p => p.Request.StartsWith("Password:"));
                foreach (var p in passPrompts)
                    p.Response = options.Password;
            };

            return auth;
        }

        static SftpFilesystem AttemptConnection(string authType, ConnectionInfo connInfo, string path)
        {
            try
            {
                var sftpFS = new SftpFilesystem(connInfo, path);
                sftpFS.Connect();
                Console.WriteLine($"Successfully authenticated with {authType}.");
                return sftpFS;
            }
            catch (SshAuthenticationException)
            {
                Console.WriteLine($"Failed to authenticate using {authType}, falling back to next auth mechanism if available.");
                return null;
            }
        }
    }
}
