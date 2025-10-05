using LightProto;
using KazusaGI_cb2.Protocol;
//using Newtonsoft.Json;
//using Newtonsoft.Json.Serialization;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Text.Json;

namespace Cb2PacketSniffer;

#pragma warning disable CS0311

public class PacketData
{
	public ushort CmdId;
	public byte[] Header = Array.Empty<byte>();
	public byte[] Payload = Array.Empty<byte>();

	public PacketData(byte[] packet)
	{
		if (packet == null || packet.Length < 8)
		{
			Console.WriteLine("Error: Packet too small.");
			return;
		}

		using var ms = new MemoryStream(packet, writable: false);
		using var br = new EndianBinaryReader(ms);

		ushort head = br.ReadUInt16BE();
		if (head != 0x4567)
		{
			Console.WriteLine($"Error: Packet header mismatch. Expected: 0x4567, got: 0x{head:X}");
			return;
		}

		CmdId = br.ReadUInt16BE();

		ushort headerLen = br.ReadUInt16BE();
		uint payloadLen = br.ReadUInt32BE();

		Header = br.ReadBytes(headerLen);

		Payload = br.ReadBytes((int)payloadLen);

		ushort trailer = br.ReadUInt16BE();
		if (trailer != 0x89AB)
		{
			Console.WriteLine($"Error: Packet trail mismatch. Expected: 0x89AB, got: 0x{trailer:X}");
			return;
		}
	}
}

internal class PacketProcessor
{
	public static int Index = 0;
	public static byte[]? key;
	public static bool doXor = false;

	private static JsonSerializerOptions options = new JsonSerializerOptions(JsonContext.Default.Options)
	{
		WriteIndented = true,
		IncludeFields = true,
		Converters = { new JsonStringEnumConverter() }
	};

	public static void Process(byte[] packet, PacketSource _source)
	{
		Index++;

		if (key != null && doXor)
			packet = Crypto.Xor(packet, key);
		PacketData packetData = new PacketData(packet);

		PacketId packetId = (PacketId)packetData.CmdId;

		if (packetId == PacketId.GetPlayerTokenReq)
		{
			using var stream = new MemoryStream(packetData.Payload);
			GetPlayerTokenReq req = Serializer.Deserialize<GetPlayerTokenReq>(stream);
			key = Crypto.NewKey(Convert.ToUInt64(req.AccountUid));
		}
		else if (packetId == PacketId.GetPlayerTokenRsp || Index >= 2)
		{ 
			doXor = true; 
		} 

		Console.WriteLine($"Received {packetId}"); //  -> {Convert.ToHexString(packetData.Payload)}

		string csORsc = _source == PacketSource.Client ? "CS" : "SC";

		File.WriteAllBytes(Path.Combine(MainApp.RawPacketDir, $"{Index}_{csORsc}_{packetId}.bin"), packetData.Payload);

		Data4Json data = new Data4Json()
		{
			PacketName = packetId.ToString(),
			CmdId = packetData.CmdId,
			Source = _source,
			Payload = GiantSwitchCase.Serialize(packetData.Payload, packetId),
			RawHeader = Convert.ToBase64String(packetData.Header),
			RawPayload = Convert.ToBase64String(packetData.Payload)
		};

		File.WriteAllText(Path.Combine(MainApp.PacketDir, $"{Index}_{csORsc}_{packetId}.json"), JsonSerializer.Serialize(data, options));
	}
}

public class Data4Json
{
	public string PacketName = String.Empty;
	public ushort CmdId;
	public PacketSource Source;
	public object Payload = new();
	public string RawHeader = String.Empty;
	public string RawPayload = String.Empty;
}