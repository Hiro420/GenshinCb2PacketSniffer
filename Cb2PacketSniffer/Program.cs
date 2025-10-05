using System;
using System.Diagnostics;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Cb2PacketSniffer.Win32Api;

namespace Cb2PacketSniffer;

public class MainApp
{
	public static IntPtr ModuleHandle = IntPtr.Zero;
	public static string ModuleDir = string.Empty;
	public static readonly string RawPacketDir = "RawPackets";
	public static readonly string PacketDir = "Packets";
	public static List<PEHeader.ExportAddressName> exportAddressNames = new List<PEHeader.ExportAddressName>();

	private static uint RunThread()
	{
		Run();
		return 0;
	}

	private static unsafe void Run()
	{
		Thread.Sleep(1000);

		GCSettings.LatencyMode = GCLatencyMode.LowLatency;
		AllocConsole();

		while (ModuleHandle == IntPtr.Zero)
		{
			if (GetModuleHandle("enet.dll") != IntPtr.Zero)
			{
				ModuleHandle = GetModuleHandle("enet.dll");
				break;
			}

			Console.WriteLine("Waiting for enet.dll to load...");

			Thread.Sleep(1000);
		}
		Console.WriteLine($"enet loaded at {ModuleHandle:X}!");

		string? exepath = Environment.ProcessPath!;
		ModuleDir = Path.Combine(Path.GetDirectoryName(exepath)!, "Genshin_Data", "Plugins", "enet.dll");

		using (FileStream fs = new FileStream(ModuleDir, FileMode.Open, FileAccess.Read))
		using (BinaryReader reader = new BinaryReader(fs))
		{
			PEHeader.DosHeader dosHeader = Misc.GetDosHeader(reader);
			exportAddressNames = Misc.GetExports(dosHeader);
		}

		if (!Directory.Exists(PacketDir))
		{
			Directory.CreateDirectory(PacketDir);
		}
		if (!Directory.Exists(RawPacketDir))
		{
			Directory.CreateDirectory(RawPacketDir);
		}

		Hooks.Init();
	}

	[UnmanagedCallersOnly(EntryPoint = "DllMain", CallConvs = [typeof(CallConvStdcall)])]
	public static bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved)
	{
		switch (fdwReason)
		{
			case 1:
				{
					IntPtr threadHandle = Win32Api.CreateThread(IntPtr.Zero, 0, RunThread, IntPtr.Zero, 0, out _);
					if (threadHandle != IntPtr.Zero)
						Win32Api.CloseHandle(threadHandle);
					break;
				}
		}

		return true;
	}
}