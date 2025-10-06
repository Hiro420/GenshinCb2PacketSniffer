using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Cb2PacketSniffer;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int enet_peer_send(nint peer, byte channelID, nint packet);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate IntPtr enet_peer_recv(nint peer, out byte channelId);

internal class Hooks
{
	public static uint packet_Send_rva = 
		MainApp.exportAddressNames.Find(e => e.names == "enet_peer_send").functionRVA;
	public static uint 
		packet_Recv_rva = MainApp.exportAddressNames.Find(e => e.names == "enet_peer_receive").functionRVA;
	private static NativeDetour<enet_peer_send>? packetSendHook;
	private static NativeDetour<enet_peer_recv>? packetRecvHook;

	private static int PacketSendDetour(nint p, byte c, nint pkt)
	{
		if (packetSendHook == null)
		{
			Console.WriteLine("PacketSendDetour called but hook is null");
			return 0;
		}
		
		ENetPacket packet = Marshal.PtrToStructure<ENetPacket>(pkt);

		Console.WriteLine($"Detected packet with {packet.dataLength} bytes");

		// Allocate and copy
		byte[] data = new byte[packet.dataLength];
		Marshal.Copy(packet.data, data, 0, (int)packet.dataLength);

		//Console.WriteLine(Convert.ToHexString(data));

		PacketProcessor.Process(data, PacketSource.Client);

		return packetSendHook.Trampoline(p, c, pkt);
	}

	private static IntPtr PacketRecvDetour(nint peer, out byte channelId)
	{
		channelId = 0;

		if (packetRecvHook == null)
		{
			Console.WriteLine("PeerReceiveDetour called but hook is null");
			return IntPtr.Zero;
		}

		// Call the original function
		IntPtr packetPtr = packetRecvHook.Trampoline(peer, out channelId);

		if (packetPtr != IntPtr.Zero)
		{
			// Marshal the native ENetPacket struct
			ENetPacket netpacket = Marshal.PtrToStructure<ENetPacket>(packetPtr);

			if (netpacket.data != IntPtr.Zero && netpacket.dataLength > 0)
			{
				try
				{
					int len = checked((int)netpacket.dataLength);
					byte[] data = new byte[len];
					Marshal.Copy(netpacket.data, data, 0, len);

					// Process the packet as a SERVER packet
					PacketProcessor.Process(data, PacketSource.Server);
				}
				catch (Exception ex)
				{
					Console.WriteLine($"PeerReceiveDetour error copying packet: {ex}");
				}
			}
		}

		return packetPtr;
	}

	public static void Init()
	{

		Console.WriteLine($"packet_Send_rva {packet_Send_rva:X} packet_Recv_rva {packet_Recv_rva:X}");

		packetSendHook = new NativeDetour<enet_peer_send>(
			MainApp.ModuleHandle + (nint)packet_Send_rva,
			PacketSendDetour
		);
		packetRecvHook = new NativeDetour<enet_peer_recv>(
			MainApp.ModuleHandle + (nint)packet_Recv_rva,
			PacketRecvDetour
		);
		packetSendHook.Attach();
		packetRecvHook.Attach();
	}
}

[StructLayout(LayoutKind.Sequential)]
public struct ENetPacket
{
	public IntPtr referenceCount;
	public uint flags;
	public IntPtr data;
	public uint dataLength;
	public IntPtr freeCallback;
	public IntPtr userData;
}

public enum PacketSource
{
	Client,
	Server
}

[StructLayout(LayoutKind.Sequential)]
public struct ENetEvent
{
	public EventType type;
	public IntPtr peer;
	public byte channelID;
	public uint data;
	public IntPtr packet;
}

public enum EventType
{
	None = 0,
	Connect = 1,
	Disconnect = 2,
	Receive = 3
}