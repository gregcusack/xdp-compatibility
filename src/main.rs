#[cfg(target_os = "linux")]
mod linux {
    use {
        agave_xdp::{
            device::{NetworkDevice, QueueId},
            tx_loop::tx_loop,
        },
        caps::{
            CapSet,
            Capability::{CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW, CAP_PERFMON},
        },
        clap::Parser,
        crossbeam_channel::bounded,
        log::*,
        rand::{Rng, rng},
        solana_clap_utils::{
            input_parsers::parse_cpu_ranges, input_validators::validate_cpu_ranges,
        },
        solana_net_utils::sockets::bind_to,
        solana_turbine::xdp::master_ip_if_bonded,
        std::{
            net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
            process::exit,
            sync::Arc,
            thread,
            time::{Duration, Instant},
        },
    };

    // Same payload sizing used by Solana packet handling (1280 - IPv6 header - UDP header).
    const DNS_RECV_BUF_SIZE: usize = 1280 - 40 - 8;
    const DNS_HEADER_LEN: usize = 12;
    const DNS_QUESTION_TRAILER_LEN: usize = 4; // QTYPE + QCLASS
    const DNS_MAX_LABEL_LEN: usize = 63;

    #[derive(Debug)]
    struct RetransmitConfig {
        interface: Option<String>,
        cpus: Vec<usize>,
        zero_copy: bool,
    }

    #[derive(Debug)]
    struct Config {
        xdp_config: RetransmitConfig,
        endpoint: SocketAddr,
        timeout_ms: u64,
    }

    enum RecvResult {
        Match,
        Mismatch,
        Timeout,
    }

    pub(crate) enum DnsValidationError {
        TxidMismatch,
        Mismatch(&'static str),
    }

    #[derive(Debug, Parser)]
    #[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"))]
    struct CliArgs {
        #[arg(
            long = "endpoint-ip",
            value_name = "IPV4",
            default_value = "8.8.8.8",
            help = "Target endpoint IPv4 address for DNS over agave-xdp"
        )]
        endpoint_ip: Ipv4Addr,

        #[arg(
            long = "experimental-retransmit-xdp-interface",
            value_name = "INTERFACE",
            requires = "retransmit_xdp_cpu_cores",
            help = "EXPERIMENTAL: The network interface to use for XDP retransmit"
        )]
        retransmit_xdp_interface: Option<String>,

        #[arg(
            long = "experimental-retransmit-xdp-cpu-cores",
            value_name = "CPU_LIST",
            value_parser = |value: &str| {
                validate_cpu_ranges(value, "--experimental-retransmit-xdp-cpu-cores")
                    .map(|_| value.to_string())
            },
            help = "EXPERIMENTAL: Enable XDP retransmit on the specified CPU cores"
        )]
        retransmit_xdp_cpu_cores: Option<String>,

        #[arg(
            long = "experimental-retransmit-xdp-zero-copy",
            requires = "retransmit_xdp_cpu_cores",
            help = "EXPERIMENTAL: Enable XDP zero copy. Requires hardware support"
        )]
        retransmit_xdp_zero_copy: bool,

        #[arg(
            long = "timeout-ms",
            value_name = "MS",
            default_value_t = 1000,
            help = "Receive timeout in milliseconds"
        )]
        timeout_ms: u64,
    }

    fn recv_until_match(udp: &UdpSocket, request: &[u8], txid: u16, timeout_ms: u64) -> RecvResult {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(timeout_ms))
            .expect("timeout must be less than u64::MAX");
        let mut buf = vec![0u8; DNS_RECV_BUF_SIZE];
        let mut saw_packet = false;
        loop {
            if Instant::now() > deadline {
                return if saw_packet {
                    RecvResult::Mismatch
                } else {
                    RecvResult::Timeout
                };
            }
            match udp.recv(&mut buf) {
                Ok(n) => {
                    saw_packet = true;
                    match validate_dns_response(&buf[..n], request, txid) {
                        Ok(()) => return RecvResult::Match,
                        Err(DnsValidationError::Mismatch(reason)) => {
                            error!("Received mismatched DNS response for txid {txid}: {reason}");
                            return RecvResult::Mismatch;
                        }
                        Err(DnsValidationError::TxidMismatch) => {
                            error!(
                                "Received DNS response for different txid while waiting for {txid}"
                            );
                        }
                    }
                }
                Err(_) => {
                    // Ignore timeout and retry until deadline.
                }
            }
        }
    }

    // Build the reverse-DNS query name for an IPv4 endpoint. This lets us probe DNS using only
    // the endpoint IP supplied by the user (no extra domain input needed).
    pub(crate) fn reverse_ptr_qname(ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    // Send one DNS query on the kernel UDP path before XDP traffic. This primes route/neighbor/NAT
    // state so first-packet behavior is less likely to hide XDP issues.
    fn warm_up_dns_path(udp: &UdpSocket, endpoint_ip: Ipv4Addr, timeout_ms: u64) {
        let warmup_txid = random_txid();
        let qname = reverse_ptr_qname(endpoint_ip);
        let Some(warmup_payload) = build_dns_query(warmup_txid, &qname) else {
            warn!("Skipping DNS warmup: failed to build warmup query");
            return;
        };
        if let Err(err) = udp.send(&warmup_payload) {
            warn!("DNS warmup send failed: {err}");
            return;
        }
        match recv_until_match(udp, &warmup_payload, warmup_txid, timeout_ms) {
            RecvResult::Match => {
                debug!("DNS warmup on kernel UDP path succeeded");
            }
            RecvResult::Mismatch => {
                warn!("DNS warmup got malformed response; continuing with XDP test");
            }
            RecvResult::Timeout => {
                warn!("DNS warmup timed out; continuing with XDP test");
            }
        }
    }

    fn encode_qname(name: &str) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for label in name.split('.') {
            let len = u8::try_from(label.len()).ok()?;
            // DNS names are encoded as a sequence of length-prefixed labels.
            out.push(len);
            out.extend_from_slice(label.as_bytes());
        }
        // Zero-length label terminates the QNAME
        out.push(0);
        Some(out)
    }

    pub(crate) fn build_dns_query(txid: u16, qname: &str) -> Option<Vec<u8>> {
        // DNS query wire layout:
        // Header (12 bytes): ID | FLAGS | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
        // Question: QNAME | QTYPE | QCLASS
        // FLAGS bit layout (MSB -> LSB):
        // QR(15) | OPCODE(14-11) | AA(10) | TC(9) | RD(8) | RA(7) | Z(6-4) | RCODE(3-0)
        let encoded_qname = encode_qname(qname)?;
        let mut dns_bytes: Vec<u8> =
            Vec::with_capacity(DNS_HEADER_LEN + encoded_qname.len() + DNS_QUESTION_TRAILER_LEN);
        dns_bytes.extend_from_slice(&txid.to_be_bytes());
        // Standard DNS query with recursion-desired set.
        dns_bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        dns_bytes.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        dns_bytes.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        dns_bytes.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        dns_bytes.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question section: QNAME | QTYPE | QCLASS
        dns_bytes.extend_from_slice(&encoded_qname); // QNAME
        dns_bytes.extend_from_slice(&12u16.to_be_bytes()); // QTYPE
        dns_bytes.extend_from_slice(&1u16.to_be_bytes()); // QCLASS
        Some(dns_bytes)
    }

    pub(crate) fn dns_question_end(packet: &[u8]) -> Option<usize> {
        if packet.len() < DNS_HEADER_LEN {
            return None;
        }
        let mut idx = DNS_HEADER_LEN;
        loop {
            if idx >= packet.len() {
                return None;
            }
            let len = packet[idx] as usize;
            idx = idx.checked_add(1)?;
            if len == 0 {
                break;
            }
            if len > DNS_MAX_LABEL_LEN || idx.checked_add(len)? > packet.len() {
                return None;
            }
            idx += len;
        }
        idx.checked_add(DNS_QUESTION_TRAILER_LEN)
            .filter(|end| *end <= packet.len())
    }

    pub(crate) fn validate_dns_response(
        packet: &[u8],
        request: &[u8],
        txid: u16,
    ) -> Result<(), DnsValidationError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(DnsValidationError::Mismatch("packet too short"));
        }
        let resp_txid = u16::from_be_bytes([packet[0], packet[1]]);
        // txid correlation prevents accepting responses for a different in-flight query.
        if resp_txid != txid {
            return Err(DnsValidationError::TxidMismatch);
        }
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if (flags & 0x8000) == 0 {
            return Err(DnsValidationError::Mismatch("not a DNS response"));
        }
        let rcode = flags & 0x000f;
        if rcode != 0 {
            return Err(DnsValidationError::Mismatch("rcode is non-zero"));
        }
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        if qdcount == 0 {
            return Err(DnsValidationError::Mismatch("missing question section"));
        }
        if ancount == 0 {
            return Err(DnsValidationError::Mismatch("no answers in response"));
        }
        // Require the echoed question to match exactly so we know the answer corresponds to our
        // endpoint-derived PTR query.
        let resp_q_end = dns_question_end(packet)
            .ok_or(DnsValidationError::Mismatch("invalid response question"))?;
        let request_question = &request[DNS_HEADER_LEN..];
        let response_question = &packet[DNS_HEADER_LEN..resp_q_end];
        if request_question != response_question {
            return Err(DnsValidationError::Mismatch("question mismatch"));
        }
        Ok(())
    }

    fn random_txid() -> u16 {
        // DNS txid is 16-bit; use a uniform non-zero value.
        rng().random_range(1..=u16::MAX)
    }

    fn parse_args() -> Config {
        let args = CliArgs::parse();

        let cpus = if let Some(cpu_list) = args.retransmit_xdp_cpu_cores.as_deref() {
            parse_cpu_ranges(cpu_list).unwrap_or_else(|err| {
                error!("--experimental-retransmit-xdp-cpu-cores {err}");
                exit(1);
            })
        } else {
            vec![0]
        };

        let xdp_config = RetransmitConfig {
            interface: args.retransmit_xdp_interface,
            cpus,
            zero_copy: args.retransmit_xdp_zero_copy,
        };
        Config {
            xdp_config,
            endpoint: SocketAddr::new(IpAddr::V4(args.endpoint_ip), 53),
            timeout_ms: args.timeout_ms,
        }
    }

    pub fn main() {
        agave_logger::setup_with_default("info");
        let config = parse_args();
        let xdp_config = &config.xdp_config;
        let zero_copy = xdp_config.zero_copy;

        let dev = match xdp_config.interface.as_ref() {
            Some(iface) => NetworkDevice::new(iface.clone()).unwrap_or_else(|e| {
                error!("Failed to open interface {iface}: {e}");
                exit(1);
            }),
            None => NetworkDevice::new_from_default_route().unwrap_or_else(|e| {
                error!("Failed to resolve default route interface: {e}");
                exit(1);
            }),
        };
        let iface = dev.name().to_string();

        let local_ip = dev
            .ipv4_addr()
            .or_else(|_| {
                master_ip_if_bonded(&iface).ok_or_else(|| {
                    std::io::Error::other("no IPv4 address on interface or bond master")
                })
            })
            .unwrap_or_else(|e| {
                error!("Failed to get IPv4 address for {iface}: {e}");
                exit(1);
            });

        let _ebpf = if zero_copy {
            for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, CAP_PERFMON] {
                if let Err(e) = caps::raise(None, CapSet::Effective, cap) {
                    error!("Failed to raise {cap:?} capability: {e}");
                    exit(1);
                }
            }

            let ebpf = match agave_xdp::load_xdp_program(&dev) {
                Ok(ebpf) => ebpf,
                Err(e) => {
                    error!("Failed to attach XDP program in DRV mode: {e}");
                    exit(1);
                }
            };
            // Keep capabilities raised until AF_XDP socket is created and bound below.
            Some(ebpf)
        } else {
            None
        };

        let endpoint = config.endpoint;
        let IpAddr::V4(endpoint_ip) = endpoint.ip() else {
            error!("Endpoint must be IPv4");
            exit(1);
        };
        // Bind a UDP socket to receive DNS responses from the endpoint.
        let udp = bind_to(IpAddr::V4(local_ip), 0).unwrap_or_else(|e| {
            error!("Failed to bind UDP socket: {e}");
            exit(1);
        });
        udp.set_read_timeout(Some(Duration::from_millis(config.timeout_ms)))
            .unwrap();
        udp.connect(endpoint).unwrap_or_else(|e| {
            error!("Failed to connect UDP socket to endpoint {endpoint}: {e}");
            exit(1);
        });
        // Warm up route/neighbor/NAT state with a normal UDP DNS exchange.
        warm_up_dns_path(&udp, endpoint_ip, config.timeout_ms);

        let (sender, receiver) = bounded::<(Vec<SocketAddr>, Vec<u8>)>(1);
        let cpu_id = xdp_config.cpus.first().copied().unwrap_or_else(|| {
            error!("No CPU core configured for XDP retransmit.");
            exit(1);
        });
        if xdp_config.cpus.len() > 1 {
            warn!("Multiple CPU cores supplied; using CPU {cpu_id} for the compatibility client.");
        }
        let src_port = udp.local_addr().unwrap().port();
        let dev = Arc::new(dev);

        if zero_copy {
            for cap in [CAP_NET_ADMIN, CAP_NET_RAW, CAP_BPF, CAP_PERFMON] {
                let _ = caps::drop(None, CapSet::Effective, cap);
            }
        }

        let (drop_sender, _drop_receiver) = bounded(1);

        let tx_thread = thread::spawn(move || {
            tx_loop(
                cpu_id,
                dev.as_ref(),
                QueueId(cpu_id as u64),
                zero_copy,
                None,
                Some(local_ip),
                src_port,
                None,
                receiver,
                drop_sender,
            );
        });

        let qname = reverse_ptr_qname(endpoint_ip);
        let txid = random_txid();
        let payload = build_dns_query(txid, &qname).unwrap_or_else(|| {
            error!("Failed to build DNS query for {qname}");
            exit(1);
        });
        sender.send((vec![endpoint], payload.clone())).unwrap();
        let result = recv_until_match(&udp, &payload, txid, config.timeout_ms);

        drop(sender);
        let _ = tx_thread.join();

        match result {
            RecvResult::Match => {
                info!("XDP DNS compatibility test passed (1/1) against endpoint IP {endpoint_ip}");
            }
            RecvResult::Mismatch => {
                error!("DNS response mismatch for single XDP probe packet");
                info!("XDP DNS compatibility test failed (0/1) against endpoint IP {endpoint_ip}");
                exit(1);
            }
            RecvResult::Timeout => {
                error!("DNS response timeout for single XDP probe packet");
                info!("XDP DNS compatibility test failed (0/1) against endpoint IP {endpoint_ip}");
                exit(1);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    pub fn main() {
        eprintln!("XDP compatibility client is Linux-only.");
        std::process::exit(1);
    }
}

fn main() {
    linux::main();
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use {
        crate::linux::{
            DnsValidationError, build_dns_query, dns_question_end, reverse_ptr_qname,
            validate_dns_response,
        },
        std::net::Ipv4Addr,
    };

    fn header_u16(packet: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([packet[offset], packet[offset + 1]])
    }

    // mock a DNS response from a request
    fn make_response_from_request(request: &[u8], txid: u16) -> Vec<u8> {
        let mut response = request.to_vec();
        response[0..2].copy_from_slice(&txid.to_be_bytes());
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, RCODE=0
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response
    }

    #[test]
    fn reverse_ptr_qname_is_encoded_in_reverse_octet_order() {
        let qname = reverse_ptr_qname(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(qname, "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn build_dns_query_sets_expected_header_and_question_fields() {
        let txid = 0x1234;
        let qname = reverse_ptr_qname(Ipv4Addr::new(8, 8, 4, 4));
        let packet = build_dns_query(txid, &qname).expect("valid qname should encode");

        assert_eq!(header_u16(&packet, 0), txid);
        assert_eq!(header_u16(&packet, 2), 0x0100); // RD set
        assert_eq!(header_u16(&packet, 4), 1); // QDCOUNT
        assert_eq!(header_u16(&packet, 6), 0); // ANCOUNT
        assert_eq!(header_u16(&packet, 8), 0); // NSCOUNT
        assert_eq!(header_u16(&packet, 10), 0); // ARCOUNT

        let q_end = dns_question_end(&packet).expect("request question should be well-formed");
        assert_eq!(header_u16(&packet, q_end - 4), 12); // QTYPE PTR
        assert_eq!(header_u16(&packet, q_end - 2), 1); // QCLASS IN
    }

    #[test]
    fn dns_question_end_rejects_truncated_qname() {
        let txid = 0x4242;
        let qname = reverse_ptr_qname(Ipv4Addr::new(1, 1, 1, 1));
        let mut packet = build_dns_query(txid, &qname).expect("query build succeeds");
        packet.pop(); // truncate final QCLASS byte
        assert!(dns_question_end(&packet).is_none());
    }

    #[test]
    fn validate_dns_response_accepts_matching_response() {
        let txid = 0x1001;
        let qname = reverse_ptr_qname(Ipv4Addr::new(9, 9, 9, 9));
        let request = build_dns_query(txid, &qname).expect("query build succeeds");
        let response = make_response_from_request(&request, txid);
        assert!(validate_dns_response(&response, &request, txid).is_ok());
    }

    #[test]
    fn validate_dns_response_ignores_wrong_txid() {
        let txid = 0x1001;
        let qname = reverse_ptr_qname(Ipv4Addr::new(9, 9, 9, 9));
        let request = build_dns_query(txid, &qname).expect("query build succeeds");
        let response = make_response_from_request(&request, txid.wrapping_add(1));
        assert!(matches!(
            validate_dns_response(&response, &request, txid),
            Err(DnsValidationError::TxidMismatch)
        ));
    }

    #[test]
    fn validate_dns_response_flags_question_mismatch() {
        let txid = 0x1001;
        let qname = reverse_ptr_qname(Ipv4Addr::new(9, 9, 9, 9));
        let request = build_dns_query(txid, &qname).expect("query build succeeds");
        let other_qname = reverse_ptr_qname(Ipv4Addr::new(1, 0, 0, 127));
        let other = build_dns_query(txid, &other_qname).expect("query build succeeds");
        let response = make_response_from_request(&other, txid);
        assert!(matches!(
            validate_dns_response(&response, &request, txid),
            Err(DnsValidationError::Mismatch("question mismatch"))
        ));
    }
}
