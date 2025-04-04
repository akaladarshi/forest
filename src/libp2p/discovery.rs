// Copyright 2019-2025 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::{
    cmp,
    collections::VecDeque,
    io, str,
    task::{Context, Poll},
    time::Duration,
};

use ahash::{HashMap, HashMapExt, HashSet, HashSetExt};
use libp2p::{
    StreamProtocol, autonat,
    core::Multiaddr,
    identify,
    identity::{PeerId, PublicKey},
    kad,
    mdns::{Event as MdnsEvent, tokio::Behaviour as Mdns},
    multiaddr::Protocol,
    swarm::{
        NetworkBehaviour, ToSwarm,
        behaviour::toggle::Toggle,
        derive_prelude::*,
        dial_opts::{DialOpts, PeerCondition},
    },
    upnp,
};
use tokio::time::Interval;
use tracing::{debug, info, trace, warn};

use crate::utils::version::FOREST_VERSION_STRING;

#[derive(NetworkBehaviour)]
pub struct DerivedDiscoveryBehaviour {
    /// Kademlia discovery.
    kademlia: Toggle<kad::Behaviour<kad::store::MemoryStore>>,
    /// Kademlia discovery for bootstrapping F3 sidecar when the main Kademlia is disabled.
    kademlia_f3_sidecar: kad::Behaviour<kad::store::MemoryStore>,
    /// Discovers nodes on the local network.
    mdns: Toggle<Mdns>,
    /// [`identify::Behaviour`] needs to be manually hooked up with [`kad::Behaviour`] to make discovery work. See <https://docs.rs/libp2p/latest/libp2p/kad/index.html#important-discrepancies>
    identify: identify::Behaviour,
    /// For details see <https://github.com/libp2p/specs/blob/master/autonat/README.md>
    autonat: autonat::Behaviour,
    /// `UPnP` port mapping that automatically try to map the ports externally to internal addresses on the gateway.
    upnp: upnp::tokio::Behaviour,
}

/// Event generated by the `DiscoveryBehaviour`.
#[derive(Debug)]
pub enum DiscoveryEvent {
    /// Event that notifies that we connected to the node with the given peer
    /// id.
    PeerConnected(PeerId),

    /// Event that notifies that we disconnected with the node with the given
    /// peer id.
    PeerDisconnected(PeerId),

    /// Discovery event
    Discovery(Box<DerivedDiscoveryBehaviourEvent>),
}

/// `DiscoveryBehaviour` configuration.
///
/// Note: In order to discover nodes or load and store values via Kademlia one
/// has to add at least one protocol.
pub struct DiscoveryConfig<'a> {
    local_peer_id: PeerId,
    local_public_key: PublicKey,
    user_defined: Vec<(PeerId, Multiaddr)>,
    target_peer_count: u64,
    enable_mdns: bool,
    enable_kademlia: bool,
    network_name: &'a str,
}

impl<'a> DiscoveryConfig<'a> {
    /// Create a default configuration with the given public key.
    pub fn new(local_public_key: PublicKey, network_name: &'a str) -> Self {
        DiscoveryConfig {
            local_peer_id: local_public_key.to_peer_id(),
            local_public_key,
            user_defined: Vec::new(),
            target_peer_count: u64::MAX,
            enable_mdns: false,
            enable_kademlia: true,
            network_name,
        }
    }

    /// Set the number of connected peers at which we pause discovery.
    pub fn target_peer_count(mut self, limit: u64) -> Self {
        self.target_peer_count = limit;
        self
    }

    /// Set custom nodes which never expire, e.g. bootstrap or reserved nodes.
    pub async fn with_user_defined(
        mut self,
        user_defined: impl IntoIterator<Item = Multiaddr>,
    ) -> anyhow::Result<Self> {
        for mut addr in user_defined.into_iter() {
            if let Some((_, Protocol::Dnsaddr(addr))) = addr
                .iter()
                .enumerate()
                .find(|(_, p)| matches!(p, Protocol::Dnsaddr(_)))
            {
                for pair in resolve_libp2p_dnsaddr(&addr).await? {
                    self.user_defined.push(pair)
                }
            } else if let Some(Protocol::P2p(peer_id)) = addr.pop() {
                self.user_defined.push((peer_id, addr))
            } else {
                anyhow::bail!("Failed to parse peer id from {addr}")
            }
        }
        Ok(self)
    }

    /// Configures if MDNS is enabled.
    pub fn with_mdns(mut self, value: bool) -> Self {
        self.enable_mdns = value;
        self
    }

    /// Configures if Kademlia is enabled.
    pub fn with_kademlia(mut self, value: bool) -> Self {
        self.enable_kademlia = value;
        self
    }

    /// Create a `DiscoveryBehaviour` from this configuration.
    pub fn finish(self) -> anyhow::Result<DiscoveryBehaviour> {
        let DiscoveryConfig {
            local_peer_id,
            local_public_key,
            user_defined,
            target_peer_count,
            enable_mdns,
            enable_kademlia,
            network_name,
        } = self;

        let mut peers = HashSet::new();
        let kademlia_opt = if enable_kademlia {
            let mut kademlia = new_kademlia(
                local_peer_id,
                StreamProtocol::try_from_owned(format!("/fil/kad/{network_name}/kad/1.0.0"))?,
            );
            for (peer_id, addr) in &user_defined {
                kademlia.add_address(peer_id, addr.clone());
                peers.insert(*peer_id);
            }
            if let Err(e) = kademlia.bootstrap() {
                warn!("Kademlia bootstrap failed: {}", e);
            }
            Some(kademlia)
        } else {
            None
        };
        let kademlia_f3_sidecar = new_kademlia(
            local_peer_id,
            StreamProtocol::try_from_owned(format!(
                "/fil/kad/f3-sidecar/{network_name}/kad/1.0.0"
            ))?,
        );

        let mdns_opt = if enable_mdns {
            Some(Mdns::new(Default::default(), local_peer_id).expect("Could not start mDNS"))
        } else {
            None
        };

        Ok(DiscoveryBehaviour {
            discovery: DerivedDiscoveryBehaviour {
                kademlia: kademlia_opt.into(),
                kademlia_f3_sidecar,
                mdns: mdns_opt.into(),
                identify: identify::Behaviour::new(
                    identify::Config::new("ipfs/0.1.0".into(), local_public_key)
                        .with_agent_version(format!("forest-{}", FOREST_VERSION_STRING.as_str()))
                        .with_push_listen_addr_updates(true),
                ),
                autonat: autonat::Behaviour::new(local_peer_id, Default::default()),
                upnp: Default::default(),
            },
            next_kad_random_query: tokio::time::interval(Duration::from_secs(1)),
            duration_to_next_kad: Duration::from_secs(1),
            pending_events: VecDeque::new(),
            n_node_connected: 0,
            peers,
            peer_info: HashMap::new(),
            target_peer_count,
            custom_seed_peers: user_defined,
            pending_dial_opts: VecDeque::new(),
        })
    }
}

pub fn new_kademlia(
    peer_id: PeerId,
    protocol: StreamProtocol,
) -> kad::Behaviour<kad::store::MemoryStore> {
    let store = kad::store::MemoryStore::new(peer_id);
    let kad_config = kad::Config::new(protocol);

    let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
    // `set_mode(Server)` fixes https://github.com/ChainSafe/forest/issues/3620
    // but it should not be required as the behaviour should automatically switch to server mode
    // according to the doc. It might be a bug in `libp2p`.
    // We should fix the bug or report with a minimal reproduction.
    kademlia.set_mode(Some(kad::Mode::Server));
    kademlia
}

/// Implementation of `NetworkBehaviour` that discovers the nodes on the
/// network.
// Behaviours that manage connections should come first, to get rid of some panics in debug build.
// See <https://github.com/libp2p/rust-libp2p/issues/4773#issuecomment-2042676966>
pub struct DiscoveryBehaviour {
    /// Derived discovery discovery.
    discovery: DerivedDiscoveryBehaviour,
    /// Stream that fires when we need to perform the next random Kademlia
    /// query.
    next_kad_random_query: Interval,
    /// After `next_kad_random_query` triggers, the next one triggers after this
    /// duration.
    duration_to_next_kad: Duration,
    /// Events to return in priority when polled.
    pending_events: VecDeque<DiscoveryEvent>,
    /// Number of nodes we're currently connected to.
    n_node_connected: u64,
    /// Keeps hash set of peers connected.
    peers: HashSet<PeerId>,
    /// Keeps hash map of peers and their information.
    pub(crate) peer_info: HashMap<PeerId, PeerInfo>,
    /// Number of connected peers to pause discovery on.
    target_peer_count: u64,
    /// Seed peers
    custom_seed_peers: Vec<(PeerId, Multiaddr)>,
    /// Options to configure dials to known peers.
    pending_dial_opts: VecDeque<DialOpts>,
}

#[derive(Default)]
pub struct PeerInfo {
    pub addresses: HashSet<Multiaddr>,
    pub identify_info: Option<identify::Info>,
}

impl DiscoveryBehaviour {
    /// Returns reference to peer set.
    pub fn peers(&self) -> &HashSet<PeerId> {
        &self.peers
    }

    /// Returns a map of peer ids and their multi-addresses
    pub fn peer_addresses(&self) -> HashMap<PeerId, HashSet<Multiaddr>> {
        self.peer_info
            .iter()
            .map(|(peer_id, info)| (*peer_id, info.addresses.clone()))
            .collect()
    }

    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peer_info.get(peer_id)
    }

    /// Bootstrap Kademlia network
    pub fn bootstrap(&mut self) -> Result<kad::QueryId, String> {
        if let Some(active_kad) = self.discovery.kademlia.as_mut() {
            active_kad.bootstrap().map_err(|e| e.to_string())
        } else {
            // Manually dial to seed peers when kademlia is disabled
            for (peer_id, address) in &self.custom_seed_peers {
                self.pending_dial_opts.push_back(
                    DialOpts::peer_id(*peer_id)
                        .condition(PeerCondition::Disconnected)
                        .addresses(vec![address.clone()])
                        .build(),
                );
            }
            Err("Kademlia is not activated".to_string())
        }
    }

    /// Gets the NAT status.
    pub fn nat_status(&self) -> autonat::NatStatus {
        self.discovery.autonat.nat_status()
    }
}

impl NetworkBehaviour for DiscoveryBehaviour {
    type ConnectionHandler = <DerivedDiscoveryBehaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = DiscoveryEvent;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.peer_info
            .entry(peer)
            .or_default()
            .addresses
            .insert(remote_addr.clone());
        self.discovery.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &libp2p::Multiaddr,
        role_override: libp2p::core::Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.peer_info
            .entry(peer)
            .or_default()
            .addresses
            .insert(addr.clone());
        self.discovery.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.discovery
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[libp2p::Multiaddr],
        effective_role: libp2p::core::Endpoint,
    ) -> Result<Vec<libp2p::Multiaddr>, ConnectionDenied> {
        self.discovery.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match &event {
            FromSwarm::ConnectionEstablished(e) => {
                if e.other_established == 0 {
                    self.n_node_connected += 1;
                    self.peers.insert(e.peer_id);
                    self.pending_events
                        .push_back(DiscoveryEvent::PeerConnected(e.peer_id));
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                if e.remaining_established == 0 {
                    self.n_node_connected -= 1;
                    self.peers.remove(&e.peer_id);
                    self.peer_info.remove(&e.peer_id);
                    self.pending_events
                        .push_back(DiscoveryEvent::PeerDisconnected(e.peer_id));
                }
            }
            _ => {}
        };
        self.discovery.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.discovery
            .on_connection_handler_event(peer_id, connection, event);
    }

    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        // Immediately process the content of `discovered`.
        if let Some(ev) = self.pending_events.pop_front() {
            return Poll::Ready(ToSwarm::GenerateEvent(ev));
        }

        // Dial to peers
        if let Some(opts) = self.pending_dial_opts.pop_front() {
            return Poll::Ready(ToSwarm::Dial { opts });
        }

        // Poll the stream that fires when we need to start a random Kademlia query.
        while self.next_kad_random_query.poll_tick(cx).is_ready() {
            if self.n_node_connected < self.target_peer_count {
                // We still have not hit the discovery max, send random request for peers.
                let random_peer_id = PeerId::random();
                debug!(
                    "Libp2p <= Starting random Kademlia request for {:?}",
                    random_peer_id
                );
                if let Some(kademlia) = self.discovery.kademlia.as_mut() {
                    kademlia.get_closest_peers(random_peer_id);
                }
            }

            // Schedule the next random query with exponentially increasing delay,
            // capped at 60 seconds.
            self.next_kad_random_query = tokio::time::interval(self.duration_to_next_kad);
            // we need to reset the interval, otherwise the next tick completes immediately.
            self.next_kad_random_query.reset();

            self.duration_to_next_kad =
                cmp::min(self.duration_to_next_kad * 2, Duration::from_secs(60));
        }

        // Poll discovery events.
        while let Poll::Ready(ev) = self.discovery.poll(cx) {
            match ev {
                ToSwarm::GenerateEvent(ev) => {
                    match &ev {
                        DerivedDiscoveryBehaviourEvent::Identify(ev) => {
                            if let identify::Event::Received { peer_id, info, .. } = ev {
                                self.peer_info.entry(*peer_id).or_default().identify_info =
                                    Some(info.clone());
                                if let Some(kademlia) = self.discovery.kademlia.as_mut() {
                                    for address in &info.listen_addrs {
                                        kademlia.add_address(peer_id, address.clone());
                                    }
                                }
                                for address in &info.listen_addrs {
                                    self.discovery
                                        .kademlia_f3_sidecar
                                        .add_address(peer_id, address.clone());
                                }
                            }
                        }
                        DerivedDiscoveryBehaviourEvent::Autonat(_) => {}
                        DerivedDiscoveryBehaviourEvent::Upnp(ev) => match ev {
                            upnp::Event::NewExternalAddr(addr) => {
                                info!("UPnP NewExternalAddr: {addr}");
                            }
                            upnp::Event::ExpiredExternalAddr(addr) => {
                                info!("UPnP ExpiredExternalAddr: {addr}");
                            }
                            upnp::Event::GatewayNotFound => {
                                info!("UPnP GatewayNotFound");
                            }
                            upnp::Event::NonRoutableGateway => {
                                info!("UPnP NonRoutableGateway");
                            }
                        },
                        DerivedDiscoveryBehaviourEvent::Kademlia(ev) => match ev {
                            // Adding to Kademlia buckets is automatic with our config,
                            // no need to do manually.
                            kad::Event::RoutingUpdated { .. } => {}
                            kad::Event::RoutablePeer { .. } => {}
                            kad::Event::PendingRoutablePeer { .. } => {
                                // Intentionally ignore
                            }
                            other => {
                                trace!("Libp2p => Unhandled Kademlia event: {:?}", other)
                            }
                        },
                        DerivedDiscoveryBehaviourEvent::KademliaF3Sidecar(_) => {}
                        DerivedDiscoveryBehaviourEvent::Mdns(ev) => match ev {
                            MdnsEvent::Discovered(list) => {
                                if self.n_node_connected >= self.target_peer_count {
                                    // Already over discovery max, don't add discovered peers.
                                    // We could potentially buffer these addresses to be added later,
                                    // but mdns is not an important use case and may be removed in future.
                                    continue;
                                }

                                // Add any discovered peers to Kademlia
                                for (peer_id, multiaddr) in list {
                                    if let Some(kad) = self.discovery.kademlia.as_mut() {
                                        kad.add_address(peer_id, multiaddr.clone());
                                    }
                                }
                            }
                            MdnsEvent::Expired(_) => {}
                        },
                    }
                    self.pending_events
                        .push_back(DiscoveryEvent::Discovery(Box::new(ev)));
                }
                ToSwarm::Dial { opts } => {
                    return Poll::Ready(ToSwarm::Dial { opts });
                }
                ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    });
                }
                ToSwarm::CloseConnection {
                    peer_id,
                    connection,
                } => {
                    return Poll::Ready(ToSwarm::CloseConnection {
                        peer_id,
                        connection,
                    });
                }
                ToSwarm::ListenOn { opts } => return Poll::Ready(ToSwarm::ListenOn { opts }),
                ToSwarm::RemoveListener { id } => {
                    return Poll::Ready(ToSwarm::RemoveListener { id });
                }
                ToSwarm::NewExternalAddrCandidate(addr) => {
                    return Poll::Ready(ToSwarm::NewExternalAddrCandidate(addr));
                }
                ToSwarm::ExternalAddrConfirmed(addr) => {
                    return Poll::Ready(ToSwarm::ExternalAddrConfirmed(addr));
                }
                ToSwarm::ExternalAddrExpired(addr) => {
                    return Poll::Ready(ToSwarm::ExternalAddrExpired(addr));
                }
                _ => {}
            }
        }

        Poll::Pending
    }
}

// Note: The function is async because the sync API `hickory_resolver::Resolver` is a wrapper of
// the async API and does not work inside another tokio runtime
async fn resolve_libp2p_dnsaddr(name: &str) -> anyhow::Result<Vec<(PeerId, Multiaddr)>> {
    use hickory_resolver::{TokioResolver, system_conf};

    let (cfg, opts) = system_conf::read_system_conf()?;
    let resolver = TokioResolver::tokio(cfg, opts);

    let name = ["_dnsaddr.", name].concat();
    let txts = resolver.txt_lookup(name).await?;

    let mut pairs = vec![];
    for txt in txts {
        if let Some(chars) = txt.txt_data().first() {
            match parse_dnsaddr_txt(chars) {
                Err(e) => {
                    // Skip over seemingly invalid entries.
                    tracing::debug!("Invalid TXT record: {:?}", e);
                }
                Ok(mut addr) => {
                    if let Some(Protocol::P2p(peer_id)) = addr.pop() {
                        pairs.push((peer_id, addr))
                    } else {
                        tracing::debug!("Failed to parse peer id from {addr}")
                    }
                }
            }
        }
    }
    Ok(pairs)
}

/// Parses a `<character-string>` of a `dnsaddr` `TXT` record.
fn parse_dnsaddr_txt(txt: &[u8]) -> io::Result<Multiaddr> {
    let s = str::from_utf8(txt).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    match s.strip_prefix("dnsaddr=") {
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing `dnsaddr=` prefix.",
        )),
        Some(a) => Ok(
            Multiaddr::try_from(a).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backon::{ExponentialBuilder, Retryable as _};
    use libp2p::{
        Swarm, Transport as _, core::transport::MemoryTransport, identity::Keypair,
        swarm::SwarmEvent,
    };
    use libp2p_swarm_test::SwarmExt as _;
    use std::str::FromStr as _;

    #[tokio::test]
    async fn resolve_libp2p_dnsaddr_test() {
        async fn run() -> anyhow::Result<()> {
            let addr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io").unwrap();
            let p = addr
                .iter()
                .find(|p| matches!(p, Protocol::Dnsaddr(_)))
                .unwrap();
            if let Protocol::Dnsaddr(name) = p {
                let pairs = resolve_libp2p_dnsaddr(&name).await?;
                assert!(!pairs.is_empty());
            } else {
                panic!("No dnsaddr protocol found");
            }

            Ok(())
        }

        run.retry(ExponentialBuilder::default()).await.unwrap();
    }

    #[tokio::test]
    async fn kademlia_test() {
        async fn new_discovery(
            keypair: Keypair,
            seed_peers: impl IntoIterator<Item = Multiaddr>,
        ) -> DiscoveryBehaviour {
            DiscoveryConfig::new(keypair.public(), "calibnet")
                .with_mdns(false)
                .with_kademlia(true)
                .with_user_defined(seed_peers)
                .await
                .unwrap()
                .target_peer_count(128)
                .finish()
                .unwrap()
        }

        async fn new_ephemeral(seed_peers: Vec<Multiaddr>) -> Swarm<DiscoveryBehaviour> {
            let identity = Keypair::generate_ed25519();
            let peer_id = PeerId::from(identity.public());
            let transport = MemoryTransport::default()
                .or_transport(libp2p::tcp::tokio::Transport::default())
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(libp2p::noise::Config::new(&identity).unwrap())
                .multiplex(libp2p::yamux::Config::default())
                .timeout(Duration::from_secs(20))
                .boxed();
            Swarm::new(
                transport,
                new_discovery(identity, seed_peers).await,
                peer_id,
                libp2p::swarm::Config::with_tokio_executor()
                    .with_idle_connection_timeout(Duration::from_secs(5)),
            )
        }

        let mut b = new_ephemeral(vec![]).await;
        b.listen().with_memory_addr_external().await;
        let b_peer_id = *b.local_peer_id();
        let b_addresses: Vec<_> = b
            .external_addresses()
            .map(|addr| {
                let mut addr = addr.clone();
                addr.push(multiaddr::Protocol::P2p(b_peer_id));
                addr
            })
            .collect();

        let mut c = new_ephemeral(vec![]).await;
        c.listen().with_memory_addr_external().await;
        let c_peer_id = *c.local_peer_id();
        if let Some(c_kad) = c.behaviour_mut().discovery.kademlia.as_mut() {
            for addr in b.external_addresses() {
                c_kad.add_address(&b_peer_id, addr.clone());
            }
        }

        let mut a = new_ephemeral(b_addresses).await;

        // Bootstrap `a` and `c`
        a.behaviour_mut().bootstrap().unwrap();
        c.behaviour_mut().bootstrap().unwrap();

        // Run event loop of `b` and `c`
        tokio::spawn(b.loop_on_next());
        tokio::spawn(c.loop_on_next());

        // Wait until `c` is connected to `a`
        a.wait(|e| match e {
            SwarmEvent::Behaviour(DiscoveryEvent::PeerConnected(peer_id)) => {
                if peer_id == c_peer_id { Some(()) } else { None }
            }
            _ => None,
        })
        .await;
    }
}
