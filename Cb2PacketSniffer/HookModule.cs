using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Cb2PacketSniffer;

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int enet_peer_send(nint peer, byte channelID, nint packet);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int enet_host_service(nint host, out ENetEvent @event, uint timeout);

internal class Hooks
{
	public static uint packet_Send_rva = 
		MainApp.exportAddressNames.Find(e => e.names == "enet_peer_send").functionRVA;
	public static uint 
		packet_Recv_rva = MainApp.exportAddressNames.Find(e => e.names == "enet_host_service").functionRVA;
	private static NativeDetour<enet_peer_send>? packetSendHook;
	private static NativeDetour<enet_host_service>? packetRecvHook;

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

	private static int PacketRecvDetour(nint host, out ENetEvent @event, uint timeout)
	{
		// Initialize the out param in case of early returns
		@event = default;

		if (packetRecvHook == null)
		{
			Console.WriteLine("PacketRecvHook called but hook is null");
			return 0;
		}

		// Call the original; it fills in @event by value (the marshaler pins stack storage and passes a pointer)
		var ret = packetRecvHook.Trampoline(host, out @event, timeout);

		// ENet: ret > 0 => an event was delivered; 0 => timeout; < 0 => error
		if (ret > 0 && @event.type == EventType.Receive && @event.packet != IntPtr.Zero)
		{
			// Read ENetPacket from the pointer in the event
			var netpacket = Marshal.PtrToStructure<ENetPacket>(@event.packet);
			Console.WriteLine($"Detected packet with {netpacket.dataLength} bytes");

			// Copy payload (note: dataLength is size_t in ENet; clamp to int for Marshal.Copy)
			int len = checked((int)netpacket.dataLength);
			var data = new byte[len];
			Marshal.Copy(netpacket.data, data, 0, len);

			// Process but do not free; the app will destroy the packet when it's done.
			PacketProcessor.Process(data, PacketSource.Server);
		}

		return ret;
	}

	public static void Init()
	{

		Console.WriteLine($"packet_Send_rva {packet_Send_rva:X} packet_Recv_rva {packet_Recv_rva:X}");

		packetSendHook = new NativeDetour<enet_peer_send>(
			MainApp.ModuleHandle + (nint)packet_Send_rva,
			PacketSendDetour
		);
		packetRecvHook = new NativeDetour<enet_host_service>(
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