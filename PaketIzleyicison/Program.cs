
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using PacketDotNet;
using SharpPcap;

record PacketInfo(
    string Protocol,
    string Source,
    string Destination,
    int Count,
    DateTime LastSeen
);

class Program
{
    static readonly object Sync = new();
    static readonly Dictionary<string, PacketInfo> Packets = new();

    static string Filter = "TÜMÜ";
    static bool Running = true;
    static long TotalPackets = 0;

    static void Main()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        var devices = CaptureDeviceList.Instance;

        Console.WriteLine("=== Koral Ağ Paket İzleyici ===\n");

        if (devices.Count == 0)
        {
            Console.WriteLine("Ağ arayüzü bulunamadı. Npcap kurulumunu kontrol et.");
            return;
        }

        for (int i = 0; i < devices.Count; i++)
            Console.WriteLine($"{i}: {devices[i].Description}");

        Console.Write("\nArayüz numarası: ");

        if (!int.TryParse(Console.ReadLine(), out int choice) ||
            choice < 0 || choice >= devices.Count)
        {
            Console.WriteLine("Geçersiz seçim.");
            return;
        }

        var device = devices[choice];

        device.OnPacketArrival += (_, e) =>
        {
            try
            {
                var raw = e.GetPacket();
                var packet = Packet.ParsePacket(
                    raw.LinkLayerType, raw.Data);

                string protocol;
                string source;
                string destination;

                // ARP, IP paketlerinden ayrı değerlendirilir.
                var arp = packet.Extract<ArpPacket>();

                if (arp != null)
                {
                    protocol = "ARP";
                    source = arp.SenderProtocolAddress.ToString();
                    destination = arp.TargetProtocolAddress.ToString();
                }
                else
                {
                    var ip = packet.Extract<IPPacket>();
                    if (ip == null) return;

                    var tcp = packet.Extract<TcpPacket>();
                    var udp = packet.Extract<UdpPacket>();

                    source = ip.SourceAddress.ToString();
                    destination = ip.DestinationAddress.ToString();

                    if (tcp != null)
                    {
                        protocol = "TCP";
                        source += ":" + tcp.SourcePort;
                        destination += ":" + tcp.DestinationPort;
                    }
                    else if (udp != null)
                    {
                        protocol = "UDP";
                        source += ":" + udp.SourcePort;
                        destination += ":" + udp.DestinationPort;
                    }
                    else if (ip.Protocol.ToString().Contains(
                        "Icmp", StringComparison.OrdinalIgnoreCase))
                    {
                        protocol = "ICMP";
                    }
                    else
                    {
                        protocol = "IP";
                    }
                }

                string key = $"{protocol}|{source}|{destination}";

                lock (Sync)
                {
                    TotalPackets++;

                    if (Packets.TryGetValue(key, out var old))
                    {
                        Packets[key] = old with
                        {
                            Count = old.Count + 1,
                            LastSeen = DateTime.Now
                        };
                    }
                    else
                    {
                        Packets[key] = new PacketInfo(
                            protocol, source, destination, 1, DateTime.Now);
                    }
                }
            }
            catch
            {
                // Bozuk veya çözümlenemeyen paketleri atla.
            }
        };

        try
        {
            device.Open(DeviceModes.Promiscuous, 1000);
            device.StartCapture();

            while (Running)
            {
                DrawScreen();

                // Klavye girişlerini kontrol et.
                DateTime until = DateTime.Now.AddMilliseconds(500);

                while (DateTime.Now < until && Running)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true).Key;

                        switch (key)
                        {
                            case ConsoleKey.D1:
                            case ConsoleKey.NumPad1:
                                Filter = "TÜMÜ";
                                break;
                            case ConsoleKey.D2:
                            case ConsoleKey.NumPad2:
                                Filter = "TCP";
                                break;
                            case ConsoleKey.D3:
                            case ConsoleKey.NumPad3:
                                Filter = "UDP";
                                break;
                            case ConsoleKey.D4:
                            case ConsoleKey.NumPad4:
                                Filter = "ARP";
                                break;
                            case ConsoleKey.D5:
                            case ConsoleKey.NumPad5:
                                Filter = "ICMP";
                                break;
                            case ConsoleKey.D6:
                            case ConsoleKey.NumPad6:
                                Filter = "IP";
                                break;
                            case ConsoleKey.R:
                                lock (Sync)
                                {
                                    Packets.Clear();
                                    TotalPackets = 0;
                                }
                                break;
                            case ConsoleKey.Q:
                            case ConsoleKey.Escape:
                                Running = false;
                                break;
                        }
                    }

                    Thread.Sleep(50);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("\nYakalama hatası: " + ex.Message);
            Console.WriteLine("Npcap ve yönetici izinlerini kontrol et.");
            Console.ReadKey();
        }
        finally
        {
            device.StopCapture();
            device.Close();
        }
    }

    static void DrawScreen()
    {
        List<PacketInfo> rows;
        long total;

        lock (Sync)
        {
            rows = Packets.Values
                .Where(p => Filter == "TÜMÜ" || p.Protocol == Filter)
                .OrderByDescending(p => p.LastSeen)
                .Take(20)
                .ToList();

            total = TotalPackets;
        }

        Console.Clear();
        Console.WriteLine("========== KORAL AĞ PAKET İZLEYİCİ ==========");
        Console.WriteLine($"Filtre: {Filter} | Yakalanan paket: {total}");
        Console.WriteLine("---------------------------------------------");
        Console.WriteLine("1 Tümü | 2 TCP | 3 UDP | 4 ARP | 5 ICMP | 6 IP");
        Console.WriteLine("R: Sayaçları sıfırla | Q: Çıkış");
        Console.WriteLine("---------------------------------------------");
        Console.WriteLine(
            $"{ "TÜR",-6} {"ADET",-7} {"KAYNAK",-28} HEDEF");
        Console.WriteLine("---------------------------------------------");

        foreach (var p in rows)
        {
            Console.WriteLine(
                $"{p.Protocol,-6} ({p.Count,-4}) " +
                $"{TrimTo(p.Source, 27),-28} {TrimTo(p.Destination, 27)}");
        }

        if (rows.Count == 0)
            Console.WriteLine("Bu filtrede henüz paket yok.");

        Console.WriteLine("\nAynı protokol ve kaynak/hedef bilgileri tek satırda birleştirilir.");
    }

    static string TrimTo(string text, int length)
    {
        if (text.Length <= length) return text;
        return text.Substring(0, length - 3) + "...";
    }
}
