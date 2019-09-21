using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
// Command line parsing
using System.CommandLine;
using System.CommandLine.Invocation;
// ssh_client.conf parsing
using SshConfigParser;
// sftp connection
using Renci.SshNet;
using Renci.SshNet.Common;

namespace SFTP_Upload
{
    class Program
    {
        RootCommand rootCommand = new RootCommand ("utility for uploading files via sftp protocol");
        public Program ()
        {
            Option optionServerConfigName = new Option ("--server", "defines a name of server configuration which will be used");
            Argument<string> argumentServerConfigName = new Argument<string> { Arity = ArgumentArity.ExactlyOne };
            Argument<string> argumentServerFingerPrint = new Argument<string> ("server-finger-print") { Arity = ArgumentArity.ExactlyOne };

            optionServerConfigName.AddAlias ("-s");
            optionServerConfigName.Argument = argumentServerConfigName;
            rootCommand.AddOption (optionServerConfigName);
            rootCommand.AddArgument (argumentServerFingerPrint);

            var commandUpload = new Command ("upload", "uploads file to the specified or the default server");
            commandUpload.AddAlias ("u");

            var argumentLocalPathFileName = new Argument<string> ("local-path-file-name") { Arity = ArgumentArity.ExactlyOne };
            commandUpload.AddArgument (argumentLocalPathFileName);

            var argumentRemotePathFileName = new Argument<string> ("remote-path-file-name") { Arity = ArgumentArity.ExactlyOne };
            commandUpload.AddArgument (argumentRemotePathFileName);

            commandUpload.Handler = CommandHandler.Create<string, string, string, string> (Upload);
            rootCommand.AddCommand (commandUpload);
        }

        static int Main (string [] args)
        {
            Program p = new Program ();
            int result = p.rootCommand.InvokeAsync (args).Result;
            return result;
        }

        public static byte [] ConvertFingerprintToByteArray (String fingerprint)
        {
            return fingerprint.Split (':').Select (s => Convert.ToByte (s, 16)).ToArray ();
        }

        void LoadSshClientConfig (string server, out string host, out int port, out string username, out string keyFileName)
        {
            string homeDir = Environment.GetFolderPath (Environment.SpecialFolder.Personal);
            string configFileName = Path.Combine (homeDir, ".ssh/config");
            var config = SshConfigParser.SshConfig.ParseFile (configFileName);
            SshHost result = config.Compute (server);
            host = (string)result ["Host"];
            port = int.Parse ((string)result ["Port"]);
            username = (string)result ["User"];
            keyFileName = (string)result ["IdentityFile"];
            if (keyFileName.StartsWith ("~/", StringComparison.InvariantCulture)) {
                keyFileName = Path.Combine (homeDir, keyFileName.Substring (2));
            }
        }

        public int Upload (string server, string serverFingerPrint, string localPathFileName, string remotePathFileName)
        {
            string host;
            int port;
            string username;
            string keyFileName;
            LoadSshClientConfig (server, out host, out port, out username, out keyFileName);

            string filePath = localPathFileName;

            var keyFile = new PrivateKeyFile (keyFileName);
            var keyFiles = new [] { keyFile };

            PrivateKeyAuthenticationMethod [] methods = new PrivateKeyAuthenticationMethod [] { new PrivateKeyAuthenticationMethod (username, keyFiles) };
            var con = new ConnectionInfo (host, port, username, methods);
            using (SftpClient sftpClient = new SftpClient (con)) {
                sftpClient.HostKeyReceived += delegate (object sender, HostKeyEventArgs e) {
                    if (e.FingerPrint.SequenceEqual (ConvertFingerprintToByteArray (serverFingerPrint)))
                        e.CanTrust = true;
                    else
                        e.CanTrust = false;
                };
                //client.BufferSize = 1024;
                PrintMessage ("Connect to server...");
                sftpClient.Connect ();
                PrintMessage ("Connection successful :)");

                PrintMessage ("Creating FileStream object to stream a file");
                FileStream fs = new FileStream (filePath, FileMode.Open);

                PrintMessage ("Uploading to server");
                sftpClient.UploadFile (fs, remotePathFileName);

                PrintMessage ("Finished");
            }

            Console.Read ();
            return 0;
        }

        private static void PrintMessage (string message)
        {
            Console.WriteLine (message);
        }
    }
}
