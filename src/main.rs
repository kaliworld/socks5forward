use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use rand::seq::SliceRandom;
use regex::Regex;
use reqwest::{Client, Url};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio::time::{Instant, interval};
use tracing::{debug, error, info, warn};

const BASE_PROXY_COOLDOWN_SECS: u64 = 3;
const MAX_PROXY_COOLDOWN_SECS: u64 = 24;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "socks5forward",
    version,
    about = "Local SOCKS5 forwarder backed by a rotating SOCKS5 proxy pool"
)]
struct Args {
    #[arg(long, help = "API key used to fetch upstream SOCKS5 proxies")]
    apikey: String,

    #[arg(long, help = "API password used to fetch upstream SOCKS5 proxies")]
    pwd: String,

    #[arg(
        long,
        default_value_t = 60,
        help = "Number of proxies requested per API refresh"
    )]
    getnum: u32,

    #[arg(
        long,
        default_value = "127.0.0.1:9999",
        help = "Local SOCKS5 listen address"
    )]
    listen: String,

    #[arg(
        long,
        default_value = "http://need1.dmdaili.com:7771/dmgetip.asp",
        help = "Proxy provider API endpoint"
    )]
    api_url: String,

    #[arg(
        long,
        default_value_t = 30,
        help = "Proxy pool refresh interval in seconds"
    )]
    refresh_secs: u64,

    #[arg(
        long,
        default_value_t = 10,
        help = "HTTP timeout for fetching proxy lists in seconds"
    )]
    request_timeout_secs: u64,

    #[arg(
        long,
        default_value_t = 5,
        help = "Max upstream proxy attempts per incoming connection"
    )]
    connect_attempts: usize,

    #[arg(
        long,
        default_value_t = 8,
        help = "Timeout for upstream proxy connect and SOCKS5 handshake in seconds"
    )]
    upstream_timeout_secs: u64,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    config: Args,
    proxy_pool: Arc<RwLock<Vec<SocketAddr>>>,
    proxy_health: Arc<RwLock<HashMap<SocketAddr, ProxyHealth>>>,
}

#[derive(Debug, Deserialize)]
struct ProxyApiResponse {
    data: Option<Vec<ProxyApiEntry>>,
}

#[derive(Debug, Deserialize)]
struct ProxyApiEntry {
    ip: String,
    port: u16,
}

#[derive(Clone, Debug, Default)]
struct ProxyHealth {
    consecutive_failures: u32,
    total_successes: u64,
    total_failures: u64,
    cooldown_until: Option<Instant>,
}

impl ProxyHealth {
    fn is_available(&self, now: Instant) -> bool {
        self.cooldown_until.is_none_or(|until| until <= now)
    }

    fn cooldown_remaining(&self, now: Instant) -> Duration {
        self.cooldown_until
            .map(|until| until.saturating_duration_since(now))
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksTarget {
    fn display(&self) -> String {
        match self {
            Self::Ip(addr) => addr.to_string(),
            Self::Domain(host, port) => format!("{host}:{port}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    if args.getnum == 0 {
        bail!("--getnum must be greater than 0");
    }
    if args.refresh_secs == 0 {
        bail!("--refresh-secs must be greater than 0");
    }
    if args.connect_attempts == 0 {
        bail!("--connect-attempts must be greater than 0");
    }
    if args.upstream_timeout_secs == 0 {
        bail!("--upstream-timeout-secs must be greater than 0");
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(args.request_timeout_secs))
        .pool_idle_timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(1)
        .build()
        .context("failed to build HTTP client")?;

    let state = AppState {
        client,
        config: args.clone(),
        proxy_pool: Arc::new(RwLock::new(Vec::new())),
        proxy_health: Arc::new(RwLock::new(HashMap::new())),
    };

    if let Err(err) = refresh_proxy_pool(&state).await {
        warn!(error = %err, "initial proxy fetch failed; server will still start with an empty pool");
    }

    let refresh_state = state.clone();
    tokio::spawn(async move {
        run_refresh_loop(refresh_state).await;
    });

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind listen address {}", args.listen))?;

    info!(listen = %args.listen, refresh_secs = args.refresh_secs, getnum = args.getnum, "SOCKS5 forwarder started");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                error!(error = %err, "failed to accept inbound connection");
                continue;
            }
        };

        let session_state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, session_state).await {
                debug!(peer = %peer_addr, error = %err, "connection finished with error");
            }
        });
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,socks5forward=info".into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn run_refresh_loop(state: AppState) {
    let mut ticker = interval(Duration::from_secs(state.config.refresh_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        if let Err(err) = refresh_proxy_pool(&state).await {
            warn!(error = %err, "proxy pool refresh failed; keeping previous pool");
        }
    }
}

async fn refresh_proxy_pool(state: &AppState) -> Result<()> {
    let url = build_api_url(&state.config)?;
    let started = Instant::now();
    let response = state
        .client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("failed to request proxy API: {url}"))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("failed to read proxy API response")?;

    if !status.is_success() {
        bail!("proxy API returned HTTP {status}: {body}");
    }

    let proxies = parse_proxy_list(&body);
    if proxies.is_empty() {
        bail!("proxy API returned no usable proxies: {body}");
    }

    reconcile_proxy_health(&state.proxy_health, &proxies).await;

    let count = proxies.len();
    *state.proxy_pool.write().await = proxies;
    info!(
        count,
        elapsed_ms = started.elapsed().as_millis(),
        "proxy pool refreshed"
    );
    Ok(())
}

fn build_api_url(args: &Args) -> Result<Url> {
    let mut url =
        Url::parse(&args.api_url).with_context(|| format!("invalid api url: {}", args.api_url))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("apikey", &args.apikey);
        pairs.append_pair("pwd", &args.pwd);
        pairs.append_pair("getnum", &args.getnum.to_string());
        pairs.append_pair("httptype", "1");
        pairs.append_pair("geshi", "2");
        pairs.append_pair("fenge", "1");
        pairs.append_pair("fengefu", "");
        pairs.append_pair("operate", "all");
    }
    Ok(url)
}

fn parse_proxy_list(body: &str) -> Vec<SocketAddr> {
    if let Some(proxies) = parse_proxy_list_from_json(body) {
        return proxies;
    }

    parse_proxy_list_from_text(body)
}

fn parse_proxy_list_from_json(body: &str) -> Option<Vec<SocketAddr>> {
    let parsed: ProxyApiResponse = serde_json::from_str(body).ok()?;
    let data = parsed.data?;
    let mut seen = HashSet::new();
    let mut output = Vec::new();

    for entry in data {
        let ip = match entry.ip.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let addr = SocketAddr::new(ip, entry.port);
        if seen.insert(addr) {
            output.push(addr);
        }
    }

    Some(output)
}

fn parse_proxy_list_from_text(body: &str) -> Vec<SocketAddr> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let regex = RE.get_or_init(|| {
        Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b").expect("proxy regex must compile")
    });

    let mut seen = HashSet::new();
    let mut output = Vec::new();

    for captures in regex.captures_iter(body) {
        let ip = captures
            .get(1)
            .and_then(|m| m.as_str().parse::<Ipv4Addr>().ok());
        let port = captures.get(2).and_then(|m| m.as_str().parse::<u16>().ok());

        if let (Some(ip), Some(port)) = (ip, port) {
            let addr = SocketAddr::new(IpAddr::V4(ip), port);
            if seen.insert(addr) {
                output.push(addr);
            }
        }
    }

    output
}

async fn reconcile_proxy_health(
    health_store: &Arc<RwLock<HashMap<SocketAddr, ProxyHealth>>>,
    proxies: &[SocketAddr],
) {
    let mut health = health_store.write().await;
    let current: HashSet<_> = proxies.iter().copied().collect();

    health.retain(|addr, _| current.contains(addr));
    for proxy in proxies {
        health.entry(*proxy).or_default();
    }
}

fn rank_proxy_candidates(
    snapshot: Vec<SocketAddr>,
    health_map: &HashMap<SocketAddr, ProxyHealth>,
    now: Instant,
    max_attempts: usize,
) -> Vec<SocketAddr> {
    let mut available = Vec::new();
    let mut cooling = Vec::new();

    for proxy in snapshot {
        let health = health_map.get(&proxy).cloned().unwrap_or_default();
        if health.is_available(now) {
            available.push((proxy, health));
        } else {
            cooling.push((proxy, health));
        }
    }

    let mut rng = rand::thread_rng();
    available.shuffle(&mut rng);
    cooling.shuffle(&mut rng);

    available.sort_by(|(_, left), (_, right)| compare_proxy_health(left, right));
    cooling.sort_by(|(_, left), (_, right)| {
        left.cooldown_remaining(now)
            .cmp(&right.cooldown_remaining(now))
            .then_with(|| compare_proxy_health(left, right))
    });

    let mut candidates: Vec<_> = available.into_iter().map(|(proxy, _)| proxy).collect();
    if candidates.len() < max_attempts {
        candidates.extend(cooling.into_iter().map(|(proxy, _)| proxy));
    }
    candidates.truncate(candidates.len().min(max_attempts));
    candidates
}

fn compare_proxy_health(left: &ProxyHealth, right: &ProxyHealth) -> Ordering {
    left.consecutive_failures
        .cmp(&right.consecutive_failures)
        .then_with(|| left.total_failures.cmp(&right.total_failures))
}

fn proxy_cooldown(failure_count: u32) -> Duration {
    let exponent = failure_count.saturating_sub(1).min(3);
    let seconds = BASE_PROXY_COOLDOWN_SECS.saturating_mul(1_u64 << exponent);
    Duration::from_secs(seconds.min(MAX_PROXY_COOLDOWN_SECS))
}

async fn handle_client(mut inbound: TcpStream, state: AppState) -> Result<()> {
    inbound.set_nodelay(true).ok();
    negotiate_client_greeting(&mut inbound).await?;

    let request = read_client_request(&mut inbound).await?;
    let request_label = request.display();

    let candidates = select_proxy_candidates(&state, state.config.connect_attempts).await;
    if candidates.is_empty() {
        write_socks_reply(&mut inbound, 0x01).await?;
        bail!("proxy pool is empty");
    }

    let mut last_err = None;
    for proxy_addr in candidates {
        match connect_via_upstream(
            proxy_addr,
            &request,
            Duration::from_secs(state.config.upstream_timeout_secs),
        )
        .await
        {
            Ok(mut upstream) => {
                mark_proxy_success(&state, proxy_addr).await;
                write_socks_reply(&mut inbound, 0x00).await?;
                match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
                    Ok(transferred) => {
                        debug!(target = %request_label, upstream = %proxy_addr, sent = transferred.0, received = transferred.1, "session closed");
                        return Ok(());
                    }
                    Err(err) if is_normal_disconnect(&err) => {
                        debug!(target = %request_label, upstream = %proxy_addr, error = %err, "session closed by peer");
                        return Ok(());
                    }
                    Err(err) => return Err(err).context("traffic relay failed"),
                }
            }
            Err(err) => {
                mark_proxy_failure(&state, proxy_addr).await;
                last_err = Some(anyhow!("upstream {proxy_addr} failed: {err}"));
            }
        }
    }

    write_socks_reply(&mut inbound, 0x01).await?;
    Err(last_err.unwrap_or_else(|| anyhow!("all upstream proxies failed")))
}

async fn select_proxy_candidates(state: &AppState, max_attempts: usize) -> Vec<SocketAddr> {
    let snapshot = state.proxy_pool.read().await.clone();
    if snapshot.len() <= 1 {
        return snapshot;
    }

    let health = state.proxy_health.read().await.clone();
    rank_proxy_candidates(snapshot, &health, Instant::now(), max_attempts)
}

async fn mark_proxy_success(state: &AppState, proxy_addr: SocketAddr) {
    let mut health = state.proxy_health.write().await;
    let entry = health.entry(proxy_addr).or_default();
    entry.total_successes = entry.total_successes.saturating_add(1);
    entry.consecutive_failures = 0;
    entry.cooldown_until = None;
}

async fn mark_proxy_failure(state: &AppState, proxy_addr: SocketAddr) {
    let mut health = state.proxy_health.write().await;
    let entry = health.entry(proxy_addr).or_default();
    entry.total_failures = entry.total_failures.saturating_add(1);
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    let cooldown = proxy_cooldown(entry.consecutive_failures);
    entry.cooldown_until = Some(Instant::now() + cooldown);

    debug!(
        proxy = %proxy_addr,
        failures = entry.consecutive_failures,
        cooldown_secs = cooldown.as_secs(),
        "upstream proxy marked unhealthy"
    );
}

fn is_normal_disconnect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof
    )
}

async fn negotiate_client_greeting(stream: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to read client greeting")?;

    if header[0] != 0x05 {
        bail!("unsupported SOCKS version: {}", header[0]);
    }

    let methods_len = header[1] as usize;
    let mut methods = vec![0u8; methods_len];
    stream
        .read_exact(&mut methods)
        .await
        .context("failed to read auth methods")?;

    let supports_no_auth = methods.contains(&0x00);
    let response = if supports_no_auth {
        [0x05, 0x00]
    } else {
        [0x05, 0xFF]
    };
    stream
        .write_all(&response)
        .await
        .context("failed to write greeting reply")?;

    if !supports_no_auth {
        bail!("client does not support no-auth SOCKS5");
    }

    Ok(())
}

async fn read_client_request(stream: &mut TcpStream) -> Result<SocksTarget> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to read request header")?;

    if header[0] != 0x05 {
        bail!("unsupported request version: {}", header[0]);
    }
    if header[2] != 0x00 {
        bail!("invalid reserved byte in SOCKS5 request");
    }
    if header[1] != 0x01 {
        write_socks_reply(stream, 0x07).await?;
        bail!("unsupported command: {}", header[1]);
    }

    read_socks_target(stream, header[3]).await
}

async fn read_socks_target(stream: &mut TcpStream, atyp: u8) -> Result<SocksTarget> {
    match atyp {
        0x01 => {
            let mut host = [0u8; 4];
            let mut port = [0u8; 2];
            stream
                .read_exact(&mut host)
                .await
                .context("failed to read IPv4 target")?;
            stream
                .read_exact(&mut port)
                .await
                .context("failed to read IPv4 port")?;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(host)), u16::from_be_bytes(port));
            Ok(SocksTarget::Ip(addr))
        }
        0x03 => {
            let len = stream
                .read_u8()
                .await
                .context("failed to read domain length")? as usize;
            if len == 0 {
                bail!("domain target length cannot be zero");
            }
            let mut host = vec![0u8; len];
            let mut port = [0u8; 2];
            stream
                .read_exact(&mut host)
                .await
                .context("failed to read domain target")?;
            stream
                .read_exact(&mut port)
                .await
                .context("failed to read domain port")?;
            let host = String::from_utf8(host).context("domain target is not valid UTF-8")?;
            Ok(SocksTarget::Domain(host, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut host = [0u8; 16];
            let mut port = [0u8; 2];
            stream
                .read_exact(&mut host)
                .await
                .context("failed to read IPv6 target")?;
            stream
                .read_exact(&mut port)
                .await
                .context("failed to read IPv6 port")?;
            let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(host)), u16::from_be_bytes(port));
            Ok(SocksTarget::Ip(addr))
        }
        _ => {
            write_socks_reply(stream, 0x08).await?;
            bail!("unsupported address type: {atyp}");
        }
    }
}

async fn connect_via_upstream(
    proxy_addr: SocketAddr,
    target: &SocksTarget,
    setup_timeout: Duration,
) -> Result<TcpStream> {
    let setup = async {
        let mut upstream = TcpStream::connect(proxy_addr)
            .await
            .with_context(|| format!("failed to connect upstream proxy {proxy_addr}"))?;
        upstream.set_nodelay(true).ok();

        upstream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .context("failed to send upstream greeting")?;

        let mut greeting_reply = [0u8; 2];
        upstream
            .read_exact(&mut greeting_reply)
            .await
            .context("failed to read upstream greeting reply")?;

        if greeting_reply[0] != 0x05 {
            bail!(
                "upstream returned invalid SOCKS version: {}",
                greeting_reply[0]
            );
        }
        if greeting_reply[1] == 0xFF {
            bail!("upstream requires unsupported authentication");
        }
        if greeting_reply[1] != 0x00 {
            bail!(
                "upstream selected unsupported auth method: {}",
                greeting_reply[1]
            );
        }

        let request = build_connect_request(target)?;
        upstream
            .write_all(&request)
            .await
            .context("failed to send upstream connect request")?;

        let mut response = [0u8; 4];
        upstream
            .read_exact(&mut response)
            .await
            .context("failed to read upstream connect reply")?;

        if response[0] != 0x05 {
            bail!(
                "upstream connect reply used invalid SOCKS version: {}",
                response[0]
            );
        }
        if response[1] != 0x00 {
            bail!(
                "upstream connect rejected request with code {}",
                response[1]
            );
        }

        discard_bound_address(&mut upstream, response[3]).await?;
        Ok(upstream)
    };

    timeout(setup_timeout, setup)
        .await
        .map_err(|_| anyhow!("upstream {proxy_addr} timed out during connect/handshake"))?
}

fn build_connect_request(target: &SocksTarget) -> Result<Vec<u8>> {
    let mut buffer = vec![0x05, 0x01, 0x00];

    match target {
        SocksTarget::Ip(SocketAddr::V4(addr)) => {
            buffer.push(0x01);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksTarget::Ip(SocketAddr::V6(addr)) => {
            buffer.push(0x04);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksTarget::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            if host_bytes.len() > u8::MAX as usize {
                bail!("target hostname too long for SOCKS5: {host}");
            }
            buffer.push(0x03);
            buffer.push(host_bytes.len() as u8);
            buffer.extend_from_slice(host_bytes);
            buffer.extend_from_slice(&port.to_be_bytes());
        }
    }

    Ok(buffer)
}

async fn discard_bound_address(stream: &mut TcpStream, atyp: u8) -> Result<()> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream
                .read_exact(&mut buf)
                .await
                .context("failed to read upstream IPv4 bind address")?;
        }
        0x03 => {
            let len = stream
                .read_u8()
                .await
                .context("failed to read upstream domain length")? as usize;
            let mut buf = vec![0u8; len + 2];
            stream
                .read_exact(&mut buf)
                .await
                .context("failed to read upstream domain bind address")?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream
                .read_exact(&mut buf)
                .await
                .context("failed to read upstream IPv6 bind address")?;
        }
        _ => bail!("upstream returned unsupported bind address type: {atyp}"),
    }

    Ok(())
}

async fn write_socks_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    let reply = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream
        .write_all(&reply)
        .await
        .context("failed to write SOCKS5 reply")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)), 15001)
    }

    #[test]
    fn parse_proxy_list_deduplicates_and_ignores_invalid_entries() {
        let input =
            "1.2.3.4:1080\nnot-a-proxy\n1.2.3.4:1080\n256.1.1.1:80\n5.6.7.8:65536\n9.9.9.9:8080";
        let proxies = parse_proxy_list(input);

        assert_eq!(
            proxies,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1080),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 8080),
            ]
        );
    }

    #[test]
    fn parse_proxy_list_supports_json_api_payload() {
        let input = r#"{"code":0,"data":[{"ip":"113.2.155.120","port":15001},{"ip":"113.2.155.120","port":15001},{"ip":"::1","port":1080},{"ip":"bad-ip","port":8080}],"success":true}"#;
        let proxies = parse_proxy_list(input);

        assert_eq!(
            proxies,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(113, 2, 155, 120)), 15001),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1080),
            ]
        );
    }

    #[test]
    fn build_connect_request_supports_domain_targets() {
        let target = SocksTarget::Domain("example.com".to_string(), 443);
        let request = build_connect_request(&target).unwrap();

        assert_eq!(request[0..4], [0x05, 0x01, 0x00, 0x03]);
        assert_eq!(request[4] as usize, "example.com".len());
        assert_eq!(&request[5..16], b"example.com");
        assert_eq!(&request[16..18], &443u16.to_be_bytes());
    }

    #[test]
    fn proxy_cooldown_caps_for_repeated_failures() {
        assert_eq!(proxy_cooldown(1), Duration::from_secs(3));
        assert_eq!(proxy_cooldown(2), Duration::from_secs(6));
        assert_eq!(proxy_cooldown(3), Duration::from_secs(12));
        assert_eq!(proxy_cooldown(4), Duration::from_secs(24));
        assert_eq!(proxy_cooldown(10), Duration::from_secs(24));
    }

    #[test]
    fn rank_proxy_candidates_prefers_available_healthy_proxies() {
        let now = Instant::now();
        let snapshot = vec![addr(1), addr(2), addr(3)];
        let health = HashMap::from([
            (
                addr(1),
                ProxyHealth {
                    total_successes: 5,
                    ..ProxyHealth::default()
                },
            ),
            (
                addr(2),
                ProxyHealth {
                    consecutive_failures: 2,
                    total_failures: 2,
                    cooldown_until: Some(now + Duration::from_secs(10)),
                    ..ProxyHealth::default()
                },
            ),
            (
                addr(3),
                ProxyHealth {
                    consecutive_failures: 1,
                    total_failures: 1,
                    ..ProxyHealth::default()
                },
            ),
        ]);

        let ranked = rank_proxy_candidates(snapshot, &health, now, 3);
        assert_eq!(ranked, vec![addr(1), addr(3), addr(2)]);
    }

    #[test]
    fn rank_proxy_candidates_falls_back_to_cooled_proxies_when_needed() {
        let now = Instant::now();
        let snapshot = vec![addr(1), addr(2)];
        let health = HashMap::from([
            (
                addr(1),
                ProxyHealth {
                    consecutive_failures: 3,
                    cooldown_until: Some(now + Duration::from_secs(20)),
                    ..ProxyHealth::default()
                },
            ),
            (
                addr(2),
                ProxyHealth {
                    consecutive_failures: 2,
                    cooldown_until: Some(now + Duration::from_secs(5)),
                    ..ProxyHealth::default()
                },
            ),
        ]);

        let ranked = rank_proxy_candidates(snapshot, &health, now, 2);
        assert_eq!(ranked, vec![addr(2), addr(1)]);
    }

    #[tokio::test]
    async fn reconcile_proxy_health_drops_stale_entries_and_keeps_current_ones() {
        let store = Arc::new(RwLock::new(HashMap::from([
            (addr(1), ProxyHealth::default()),
            (addr(2), ProxyHealth::default()),
        ])));

        reconcile_proxy_health(&store, &[addr(2), addr(3)]).await;

        let health = store.read().await;
        assert!(health.contains_key(&addr(2)));
        assert!(health.contains_key(&addr(3)));
        assert!(!health.contains_key(&addr(1)));
    }

    #[test]
    fn normal_disconnect_detection_matches_common_peer_closes() {
        assert!(is_normal_disconnect(&std::io::Error::from(
            ErrorKind::BrokenPipe
        )));
        assert!(is_normal_disconnect(&std::io::Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(is_normal_disconnect(&std::io::Error::from(
            ErrorKind::UnexpectedEof
        )));
        assert!(!is_normal_disconnect(&std::io::Error::from(
            ErrorKind::TimedOut
        )));
    }
}
