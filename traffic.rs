use pcap::{Capture, Packet};

fn main() {
    // Open a live capture on the first available network interface
    let mut cap = Capture::from_device("en0").unwrap()
        .promisc(true)
        .snaplen(65535)
        .open().unwrap();

    // Loop over each packet in the capture
    while let Ok(packet) = cap.next() {
        // Analyze the packet and flag it as malicious or non-malicious based on specific criteria
        let packet_type = analyze_packet(&packet);

        // Print the packet header and data, along with the flag
        println!("Packet type: {:?}", packet_type);
        println!("Packet header: {:?}", packet.header);
        println!("Packet data: {:?}", packet.data);
    }
}

// Analyze the packet and flag it as malicious or non-malicious based on specific criteria
fn analyze_packet(packet: &Packet) -> String {
    // Check if the packet data contains a known exploit or malware signature
    if packet.data.contains(b"exploit") || packet.data.contains(b"malware") {
        return String::from("malicious");
    }

    // Check if the packet is coming from or going to a known malicious IP address
    if packet.header.len > 20 && (packet.header.data[12..16] == [10, 0, 0, 1] || packet.header.data[16..20] == [10, 0, 0, 2]) {
        return String::from("malicious");
    }

    // If none of the criteria above are met, flag the packet as non-malicious
    String::from("non-malicious")
}
