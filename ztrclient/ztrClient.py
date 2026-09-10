from utils.crypt_bot import CryptBot
import socket
import sys
import hashlib
import secrets
import time
import json
import random
import string
import os
import struct
import base64
from pathlib import Path
import sqlite3
import logging

def sha256(msg: str):
    return hashlib.sha256(msg.encode()).hexdigest()


class ZTRClientError(Exception):
    """Base class for every exception ztrClient.py raises on purpose."""


class ConfigError(ZTRClientError):
    """The .ztr config file is missing, unreadable, or malformed."""


class ConfigNotFoundError(ConfigError):
    """No .ztr file at the expected routes/ path."""


class ConfigParseError(ConfigError):
    """The .ztr file exists but isn't valid JSON."""


class ConfigFieldError(ConfigError):
    """The .ztr file is valid JSON but is missing a field this client needs."""


class CryptoError(ZTRClientError):
    """Key generation, encryption, decryption, or signature verification failed."""


class TunnelError(ZTRClientError):
    """Base class for anything that goes wrong authorizing or using a tunnel."""


class NetworkError(TunnelError):
    """Couldn't reach a hop, or lost the connection to one, over the network."""


class ProtocolError(TunnelError):
    """A hop responded, but the response wasn't decryptable, verifiable, or valid JSON."""


class CacheError(ZTRClientError):
    """The local SQLite tunnel cache failed to read or write."""


class RelayConfig:
    def __init__(self, config_file = None):
        self.SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.config_path = f"{self.SCRIPT_DIR}/routes/{config_file}"
        self.config = self._load_config()
        self.PUB_PATH = f"{self.SCRIPT_DIR}/{self.settings("pub_path_dir")}"
        self.LOG_PATH = f"{self.SCRIPT_DIR}/logs"
        self._prepare()
        
        # logging.getLogger(__name__) returns the SAME object across every
        # RelayConfig/RelayClient instance in this process — only attach a
        # handler once, or each new instance piles on another FileHandler
        # and every line gets logged once per instance alive.
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            try:
                file_handler = logging.FileHandler(f"{self.LOG_PATH}/ztrclient.log")
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except OSError:
                # Logging should never be the reason the tunnel itself fails —
                # fall back to stderr if the log file can't be opened.
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(formatter)
                self.logger.addHandler(stream_handler)
                self.logger.warning(
                    f"couldn't open {self.LOG_PATH}/ztrclient.log for writing — logging to stderr instead"
                )

        # Separate from ztrclient.log on purpose — a hop rejecting the
        # authorization request (status: False) is the one failure mode a
        # user has no other way to see (set_log() only prints when
        # debug=True), so it gets its own always-on file a support agent
        # can ask for directly, without wading through debug noise.
        # propagate=False keeps it out of ztrclient.log's handler too.
        self.ra_error_logger = logging.getLogger(f"{__name__}.ra_error")
        self.ra_error_logger.setLevel(logging.ERROR)
        self.ra_error_logger.propagate = False
        if not self.ra_error_logger.handlers:
            ra_error_formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
            try:
                ra_error_handler = logging.FileHandler(f"{self.LOG_PATH}/ztrclient_ra-error.log")
                ra_error_handler.setFormatter(ra_error_formatter)
                self.ra_error_logger.addHandler(ra_error_handler)
            except OSError:
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(ra_error_formatter)
                self.ra_error_logger.addHandler(stream_handler)
                self.logger.warning(
                    f"couldn't open {self.LOG_PATH}/ztrclient_ra-error.log for writing — logging to stderr instead"
                )

    def _load_config(self):
        try:
            with open(self.config_path, "r") as f:
                content = f.read()
        except FileNotFoundError as e:
            raise ConfigNotFoundError(
                f"no .ztr config at {self.config_path} — place it in routes/ next to ztrClient.py"
            ) from e
        except OSError as e:
            raise ConfigError(f"couldn't read {self.config_path}: {e}") from e

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigParseError(f"{self.config_path} isn't valid JSON: {e}") from e

    def _prepare(self):
        try:
            os.makedirs(self.PUB_PATH, exist_ok=True)
            os.makedirs(self.LOG_PATH, exist_ok=True)
        except OSError as e:
            raise ConfigError(f"couldn't create required directories under {self.SCRIPT_DIR}: {e}") from e

    def service(self, name):
        try:
            return self.config["services"][name]
        except KeyError as e:
            raise ConfigFieldError(f"no service '{name}' defined in this .ztr config") from e

    def settings(self, tof):
        try:
            return self.config["hop_settings"][tof]
        except KeyError as e:
            raise ConfigFieldError(f"missing hop_settings.{tof} in this .ztr config") from e

    def pub_path_by_address(self, address: str):
        return f"{self.PUB_PATH}/{sha256(address)[:8]}.pem"
    
    @property
    def route_id(self):
        try:
            return self.config["route_id"]
        except KeyError as e:
            raise ConfigFieldError("missing 'route_id' in this .ztr config") from e

    @property
    def secret_key(self):
        try:
            return self.config["secret_key"]
        except KeyError as e:
            raise ConfigFieldError("missing 'secret_key' in this .ztr config") from e

    @property
    def client_id(self):
        try:
            return self.config["identifier"]
        except KeyError as e:
            raise ConfigFieldError("missing 'identifier' in this .ztr config") from e

    @property
    def ra_port(self):
        """ This is the port to controll a hop"""
        return self.settings("ra_port")

    def get_chain(self):
        try:
            chain = self.config["chain"]
        except KeyError as e:
            raise ConfigFieldError("missing 'chain' in this .ztr config") from e
        if not isinstance(chain, list) or len(chain) < 2:
            raise ConfigFieldError("'chain' must list at least 2 hops (entry + exit)")

        l = []
        for hop in chain:
            try:
                pubkey = hop["pubkey"]
                address = hop["address"]
            except (KeyError, TypeError) as e:
                raise ConfigFieldError(f"a hop in 'chain' is missing 'pubkey' or 'address': {hop}") from e
            try:
                with open(self.pub_path_by_address(address), "w") as f:
                    f.write(pubkey)
            except OSError as e:
                raise ConfigError(f"couldn't write cached pubkey for hop {address}: {e}") from e
            l.append(address)
        return l

def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Helper function to reliably read an exact number of bytes from a socket."""
    data = bytearray()
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            raise ConnectionError("Socket connection closed before receiving full message.")
        data.extend(packet)
    return bytes(data)


# Same module name as RelayConfig.logger (logging.getLogger(__name__) always
# returns the same object for a given name), so this ends up in the same
# ztrclient.log — as long as a RelayConfig/RelayClient exists first to attach
# the handler. TunnelCache always does (RelayClient.__init__ creates it right
# after super().__init__()), so this needs no setup of its own.
_cache_logger = logging.getLogger(__name__)


class TunnelCache:
    def __init__(self, db_path="tunnel_cache.db"):
        self.SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.db_path = f"{self.SCRIPT_DIR}/{db_path}"
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tunnel_cache (
                        session_id TEXT PRIMARY KEY,
                        tunnel_id TEXT NOT NULL,
                        response_json TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        port INTEGER
                    )
                """)
                # A tunnel_cache.db from before port tracking existed won't
                # have this column — the CREATE above is a no-op against an
                # existing table, so add it explicitly. Fails harmlessly
                # (already exists) on a fresh db, where CREATE just made it.
                try:
                    conn.execute("ALTER TABLE tunnel_cache ADD COLUMN port INTEGER")
                except sqlite3.OperationalError:
                    pass
                conn.commit()
        except sqlite3.Error as e:
            raise CacheError(f"couldn't initialize tunnel cache at {self.db_path}: {e}") from e

    def get(self, tunnel_id: str):
        """Retrieve non-expired tunnel response, or (None, None) on a miss
        or a cache failure — a broken cache should mean re-authorizing the
        tunnel, not crashing the whole client."""
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Clean expired records while querying
                cursor.execute("DELETE FROM tunnel_cache WHERE expires_at <= ?", (now,))
                conn.commit()

                cursor.execute(
                    "SELECT response_json, session_id FROM tunnel_cache WHERE tunnel_id = ? AND expires_at > ?",
                    (tunnel_id, now)
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0]), row[1]
        except (sqlite3.Error, json.JSONDecodeError) as e:
            _cache_logger.warning(f"tunnel cache read failed, treating as a miss: {e}")
            return None, None
        return None, None

    def delete(self, tunnel_id: str):
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM tunnel_cache WHERE tunnel_id = ? ", (tunnel_id,))
                conn.commit()
        except sqlite3.Error as e:
            _cache_logger.warning(f"tunnel cache delete failed for {tunnel_id[:8]}...: {e}")

    def set(self, tunnel_id: str,session_id:str, response_dict: dict, ttl_seconds: int, port: int = None):
        """Store response in cache with expiration. Best-effort — a failed
        write just means the next call re-authorizes instead of hitting the
        cache, not a reason to fail the whole tunnel request. `port` is
        recorded purely so port_usage_counts() below can see it — it plays
        no role in cache lookup/expiry."""
        expires_at = time.time() + ttl_seconds
        response_json = json.dumps(response_dict)
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO tunnel_cache (tunnel_id,session_id, response_json, expires_at, port)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        tunnel_id = excluded.tunnel_id,
                        response_json=excluded.response_json,
                        expires_at=excluded.expires_at,
                        port=excluded.port
                """, (tunnel_id,session_id,response_json, expires_at, port))
                conn.commit()
        except sqlite3.Error as e:
            _cache_logger.warning(f"tunnel cache write failed for {tunnel_id[:8]}...: {e}")

    def port_usage_counts(self, candidate_ports: list) -> dict:
        """
        Count of currently-active (non-expired, cached) tunnels per port,
        for each of candidate_ports — 0 for any with none. Local-only
        signal: this machine's tunnel_cache.db (shared by every ztrClient
        process using the same db_path, which is every one by default,
        since it's SCRIPT_DIR-relative), not the entry hop's own real
        traffic — used by RelayClient's automatic port selection (see
        RelayClient.__init__) to spread new tunnels across
        hop_settings.services_ports instead of always picking the first.
        Falls back to reporting every candidate as equally free (all 0) on
        a read failure, same reasoning as get()/set() — an unreadable
        cache should never block port selection.
        """
        now = time.time()
        counts = {p: 0 for p in candidate_ports}
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM tunnel_cache WHERE expires_at <= ?", (now,))
                conn.commit()
                cursor.execute(
                    "SELECT port, COUNT(*) FROM tunnel_cache WHERE expires_at > ? GROUP BY port",
                    (now,)
                )
                for port, count in cursor.fetchall():
                    if port in counts:
                        counts[port] = count
        except sqlite3.Error as e:
            _cache_logger.warning(f"tunnel cache port-usage query failed, treating all candidate ports as equally free: {e}")
        return counts

class RelayClient(RelayConfig):
    """
    Sets up hop routing authorization across a chain of proxies, then
    sends an encrypted 'void' request to the final HOST/PORT with an
    end-state payload for the target.
    """

    def __init__(self, target_host: str, port: int = None, db_name: str = "pr.db", debug=False, config_file = None):
        super().__init__(config_file=config_file)
        self.tunnel_cache = TunnelCache()
        self.TARGET_HOST = target_host
        # port=None auto-selects one of hop_settings.services_ports based on
        # local usage — see _auto_select_port(). Needs self.tunnel_cache and
        # RelayConfig's settings() (from super().__init__() above) already
        # in place, which is why this can't move any earlier.
        if port is None:
            port = self._auto_select_port()
        # PORT and TARGET_PORT are NOT the same thing, even though
        # TARGET_PORT defaults to whatever PORT is passed in here. PORT is
        # this tunnel's own listening_port, sent to the entry hop as part of
        # the hop-authorization request (see request_hop_authorization()) —
        # it identifies this session, it isn't where traffic ends up. The
        # real destination is TARGET_HOST:TARGET_PORT — where the exit hop
        # actually connects — and it can be changed independently at any
        # time before authorization via set_target_port().
        self.PORT = port
        self.TARGET_PORT = port # by default — override with set_target_port()
        self.DB_PATH = f"{self.SCRIPT_DIR}/{db_name}"
        self.failed_hops = set()

        self.chain = self.get_chain()

        self.entry_hop = self.chain[0] # ENTRY HOP
        self.last_middle_hop = self.chain[-2] # PRE EXIT HOP (SENTRY)
        self.exit_hop = self.chain[-1] # EXIT HOP (RELAY)

        self.hops = self.chain.copy()
        self.hops.pop()

        try:
            self.crypt = CryptBot(
                pathPrivateKey=f"{self.SCRIPT_DIR}/privateKey.pem",
                pathPublicKey=f"{self.SCRIPT_DIR}/publicKey.pem",
                pathRecipientPublicKey=self.proxy_pub_path(self.hops[0])
            )
            self.crypt.create_keys(rsa_size=2048, reuse=True)
        except Exception as e:
            self.logger.error(f"local keypair setup failed: {e}")
            raise CryptoError(f"couldn't set up local keypair: {e}") from e

        # hops_instructions() encrypts per-hop now, so self.crypt has to
        # exist first — this used to run before the crypt setup above,
        # back when it just built a plain dict.
        self.HI = self.hops_instructions(self.hops)
        self.debug=debug
        self.session_id = None
        self.tunnel_id = None
        self.worker_id = ""
        self.timing_defense = False
        self.secure_transport = False
        self.we_recipient_pubkey_path = None
        # Deliberately never the same object as self.crypt (which signs/
        # encrypts hop-authorization traffic with this client's own
        # relay identity) — separation of duties: a target reached via
        # with_encryption() should never need to know or trust this
        # client's hop-facing keypair, only whatever keypair it was
        # actually given here.
        self._e2e_crypt = None

    def _auto_select_port(self) -> int:
        """
        Picks a port from hop_settings.services_ports automatically, based on
        how many currently-active (non-expired) tunnels this machine already
        has open per port — least-used wins, random tiebreak. Local knowledge
        only: this can't see the entry hop's own real traffic, just what
        tunnel_cache.db (shared across every ztrClient process on this
        machine, unless db_name/SCRIPT_DIR differ) has recorded.
        """
        candidates = self.settings("services_ports")
        if not isinstance(candidates, list) or not candidates:
            raise ConfigFieldError("hop_settings.services_ports must be a non-empty list to auto-select a port")
        usage = self.tunnel_cache.port_usage_counts(candidates)
        least = min(usage.values())
        least_used_ports = [p for p, count in usage.items() if count == least]
        return random.choice(least_used_ports)

    def set_target_port(self,port: int):
        """ This is actually where the exit hop will connect to {TARGET_HOST}:{self.TARGET_PORT}"""
        self.TARGET_PORT = port
    @property
    def __ENTRY__(self):
        return self.chain[0]

    @property
    def __SENTRY__(self):
        return self.hops[-1]

    def __repr__(self):
        return f"<ZTRC hops_len<{len(self.chain)}>, session<{self.session_id}>, tunnel<{self.tunnel_id}>>"
    # ---------- static/helper utilities ----------

    @staticmethod
    def sha256(msg: str) -> str:
        return hashlib.sha256(msg.encode()).hexdigest()

    def proxy_pub_path(self, ip: str) -> str:
        return self.pub_path_by_address(address=ip)

    @staticmethod
    def next_after(lst, item):
        try:
            i = lst.index(item)
            return lst[i + 1] if i + 1 < len(lst) else item
        except ValueError:
            return item

    def hops_instructions(self, hops: list) -> list:
        """
            One encrypted blob per hop, in chain order — not a dict every
            hop could read in full. A hop only ever decrypts position 0 of
            whatever list it receives (always its own, since the list is
            built in this order and each hop pops itself off before
            forwarding the rest), learns its own next-hop address, and
            forwards the remainder onward — still fully opaque to it.
            hops excludes the exit (see __init__), so the last hop here is
            last_middle_hop; its "next hop" is the real exit address, same
            as every other hop's — no None/sentinel case needed.
        """
        instructions = []
        for i, hop in enumerate(hops):
            next_hop = hops[i + 1] if i < len(hops) - 1 else self.exit_hop
            blob = self._encrypt_for(hop, next_hop)
            instructions.append(base64.b64encode(blob).decode("ascii"))
        return instructions

    def struct_payload(self, data: dict) -> str:
        self.session_id ="ZTR_" + self.sha256(secrets.token_urlsafe(64) + self.config['identifier'])[4:]
        data["nonce"] = secrets.token_urlsafe(64)
        data["session_id"] = self.session_id
        data["timestamp"] = int(time.time())
        data["route_id"] = self.route_id
        data["client_id"] = self.client_id
        data["key"] = self.secret_key
        data["pubkey_id"] = self.settings("encryptions")["pubkey_id"]
        if self.timing_defense:
            data["with_delay"] = True
            data["with_decoys"] = True
        if self.secure_transport:
            data["secure_transport"] = True
        return json.dumps(data)
            
    def _encrypt_sign(self, data: str) -> bytes:
        try:
            return self.crypt.encrypt_sign_BytesPayload(data.encode("utf-8"))
        except Exception as e:
            raise CryptoError(f"failed to encrypt/sign outgoing payload: {e}") from e

    def _decrypt_verify(self, data: bytes):
        try:
            return self.crypt.decrypt_msg_verifyBytesPayload(data, as_="bytes").decode("utf-8")
        except Exception as e:
            raise CryptoError(f"failed to decrypt/verify incoming payload: {e}") from e

    def _encrypt_for(self, hop_address: str, plaintext: str) -> bytes:
        """
            Encrypt+sign plaintext specifically for one hop's cached pubkey —
            leaves self.crypt's recipient pointed at that hop afterward, so
            call this last if you still need it pointed at a different one
            (e.g. the entry) right after.
        """
        try:
            self.crypt.set_recipient_pubkey(self.proxy_pub_path(hop_address))
        except Exception as e:
            raise CryptoError(f"couldn't load cached pubkey for hop {hop_address}: {e}") from e
        return self._encrypt_sign(plaintext)

    def _send_framed(self, sock: socket.socket, payload: bytes):
        header = struct.pack(">I", len(payload))
        sock.sendall(header + payload)
    # ---------- main workflow ----------
    
    def _shuffle_hops(self):
        E = self.hops[0]
        rst = self.hops[1:]
        random.shuffle(rst)
        self.hops = [E] + rst
        self.HI = self.hops_instructions(self.hops)

    def hopsKeyRepresentation(self):
        return self.sha256("-".join(sorted(self.hops)))

    def with_worker_id(self, worker_id:str):
        self.worker_id = worker_id
        return self

    def with_timing_defense(self, enabled: bool = True):
        self.timing_defense = enabled
        return self
    
    def with_encryption(self, recipient_pubkey_path: str = None, own_private_key: str = None, own_public_key: str = None, enabled: bool = True):
        """
        `enabled` alone (no recipient_pubkey_path) just sets secure_transport
        — communicated to the hop chain so the exit hop also encrypts its
        own final leg to target_host:target_port (see struct_payload()).
        That's the whole original behavior, and every existing caller that
        only wants this (ZtrRequestsClient, RCWorkers — they already run
        their own separate end-to-end crypto layer) keeps working exactly
        as before.

        Passing `recipient_pubkey_path` additionally makes send_HTH/recv_HTH
        themselves sign+encrypt/decrypt+verify the payload end-to-end
        against it, using a dedicated keypair — own_private_key/
        own_public_key if given, otherwise one generated on first use
        (reused after that) at e2ePrivateKey.pem/e2ePublicKey.pem next to
        this script. Deliberately never self.crypt's own keypair (used for
        hop authorization) — keep this identity separate, so a target only
        ever needs to trust the keypair you actually hand it here, not this
        client's relay identity.
        """
        self.secure_transport = enabled
        if recipient_pubkey_path is None:
            return self

        self.we_recipient_pubkey_path = recipient_pubkey_path
        try:
            self._e2e_crypt = CryptBot(
                pathPrivateKey=own_private_key or f"{self.SCRIPT_DIR}/e2ePrivateKey.pem",
                pathPublicKey=own_public_key or f"{self.SCRIPT_DIR}/e2ePublicKey.pem",
                pathRecipientPublicKey=recipient_pubkey_path,
            )
            self._e2e_crypt.create_keys(rsa_size=2048, reuse=True)
        except Exception as e:
            raise CryptoError(f"couldn't set up end-to-end encryption keypair: {e}") from e
        return self
    
    def set_log(self, msg:str):
        if self.debug:
            self.logger.info(msg)

    def create_tunnel_id(self, ttl:int=86400, native=True):
        components = [str(x) for x in [
            self.route_id,
            self.hopsKeyRepresentation(), 
            self.TARGET_PORT, 
            self.PORT, 
            self.TARGET_HOST, 
            ttl, 
            int(native), 
            self.worker_id,
            self.client_id,
            self.secret_key,
            self.secure_transport,
            self.timing_defense
        ]]
        return self.sha256("_".join(components))

    def request_hop_authorization(self, ttl:int=86400, native=True):
        """
            Ask the first hop for routing permission (hrr) across the chain.
            data_sent_from((h[n] to h[n + 1])...len(h))
        """
        self.set_log("request_hop_authorization")
        self.tunnel_id = self.create_tunnel_id(ttl=ttl, native=native)
        #1. Check SQLite Cache
        cached_response, session_id = self.tunnel_cache.get(self.tunnel_id)
        if cached_response is not None:
            self.set_log(f"[CACHE HIT] Returning cached HRR authorization for tunnel {self.tunnel_id[:8]}...")
            self.session_id = session_id
            return cached_response

        self._shuffle_hops()
        finalDst = f"{self.TARGET_HOST}:{self.TARGET_PORT}"
        try:
            final_dst_for_exit = base64.b64encode(
                self._encrypt_for(self.exit_hop, finalDst)
            ).decode("ascii")
        except CryptoError as e:
            self.logger.warning(f"[request_hop_authorization] {e}")
            return None

        json_data = self.struct_payload({
            "cmd": "hrr",
            "instructions": self.HI,
            "listening_port": self.PORT,
            "final_dst": final_dst_for_exit,
            "ttl": ttl,
            "native": int(native)
        })
        try:
            conn = socket.create_connection((self.hops[0], self.ra_port), timeout=10)
        except OSError as e:
            self.logger.warning(f"[request_hop_authorization] couldn't reach hop {self.hops[0]}:{self.ra_port}: {e}")
            return None

        try:
            with conn as s:
                payload = self._encrypt_for(self.hops[0], json_data)
                try:
                    self._send_framed(s, payload)
                    rh = recv_exact(s, 4)
                    (length,) = struct.unpack(">I", rh)
                    response = recv_exact(s, length)
                except (OSError, ConnectionError) as e:
                    raise NetworkError(f"connection to hop {self.hops[0]} dropped: {e}") from e
                except struct.error as e:
                    raise ProtocolError(f"malformed length header from hop {self.hops[0]}: {e}") from e

            decrypted_msg = self._decrypt_verify(response)  # raises CryptoError
            try:
                decrypted_msg = json.loads(decrypted_msg)
            except json.JSONDecodeError as e:
                raise ProtocolError(f"hop {self.hops[0]} sent a response that wasn't valid JSON: {e}") from e
        except (NetworkError, ProtocolError, CryptoError) as e:
            self.logger.warning(f"[request_hop_authorization] {e}")
            return None

        self.set_log(f"HOP[{self.hops[0]}..] says {decrypted_msg.get('status')}")

        if not decrypted_msg.get("status"):
            self.ra_error_logger.error(
                f"error_code={decrypted_msg.get('error_code')} error={decrypted_msg.get('error')}"
            )

        if decrypted_msg.get("error_code") == 9: # HOP that failed
            decrypted_msg['@sys_next_hop'] = self.next_after(self.hops, decrypted_msg.get('hop_id'))
            self.failed_hops.add(decrypted_msg['@sys_next_hop'])

        if decrypted_msg.get("status"):
            self.tunnel_cache.set(self.tunnel_id,self.session_id,decrypted_msg, ttl_seconds=ttl, port=self.PORT)

        return decrypted_msg

    def force_request_hop_authorization(self, ttl=86400,native=True, max_retries=5):
        for attempt in range(max_retries):
            self.tunnel_cache.delete(self.tunnel_id)

            self.hops = [h for h in self.hops if h not in self.failed_hops]
            if len(self.hops) < 2:
                return None
            res = self.request_hop_authorization(ttl=ttl, native=native)

            if res and  res.get("status"):
                return res

        return None

    def set_tunnel(self, reset=False, ttl:int=86400, native=True):
        result = None
        if not reset:
            result = self.request_hop_authorization(ttl=ttl, native=native)
        else:
            result = self.force_request_hop_authorization(ttl=ttl, native=native)
        if result and result.get("status"):
            self.set_log(f"[set_tunnel] OK")
        elif not result:
            self.set_log(f"[set_tunnel] Failed Didnt reach Entry Hop")
        else:
            self.set_log(f"[set_tunnel] Failed with error({result.get('error_code')}, {result.get('error')})")
        return result

    def send_HTH(self,sock: socket.socket, payload: bytes, session_id:str):
        """ Use this send your data"""
        # session_id len is always 64
        session_bytes = session_id.encode("utf-8")

        if self._e2e_crypt is not None:
            # Set only if with_encryption() was given a recipient_pubkey_path
            # — independent of self.secure_transport, which just flags the
            # hop chain for its own unrelated final-leg encryption (see
            # struct_payload()). self._e2e_crypt, never self.crypt — that's
            # a completely different CryptBot instance used for hop
            # authorization traffic; keeping them separate is the point.
            try:
                payload = self._e2e_crypt.encrypt_sign_BytesPayload(payload)
            except Exception as e:
                raise CryptoError(f"failed to encrypt outgoing end-to-end payload: {e}") from e

        header = struct.pack(">I64s", len(payload), session_bytes)
        # Send header (68 bytes total) + payload
        try:
            sock.sendall(header + payload)
        except OSError as e:
            raise NetworkError(f"failed to send data over the tunnel: {e}") from e

    def recv_HTH(self, sock: socket.socket):
        """ Use this to recv your data is you had Native = True"""
        HEADER_FORMAT = ">I64s"
        HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

        try:
            header_bytes = recv_exact(sock, HEADER_SIZE)
            payload_len, session_bytes = struct.unpack(HEADER_FORMAT, header_bytes)
        except (OSError, ConnectionError) as e:
            raise NetworkError(f"connection dropped while receiving data over the tunnel: {e}") from e
        except struct.error as e:
            raise ProtocolError(f"malformed header received over the tunnel: {e}") from e

        session_id = session_bytes.decode("utf-8")

        try:
            payload = recv_exact(sock, payload_len)
        except (OSError, ConnectionError) as e:
            raise NetworkError(f"connection dropped while receiving data over the tunnel: {e}") from e

        if self._e2e_crypt is not None:
            # Mirrors send_HTH's check — see with_encryption(). Independent
            # of self.secure_transport, same reasoning as send_HTH above.
            try:
                decrypted = self._e2e_crypt.decrypt_msg_verifyBytesPayload(payload, as_="bytes")
            except Exception as e:
                raise CryptoError(f"failed to decrypt incoming end-to-end payload: {e}") from e
            if decrypted is None:
                raise CryptoError(
                    "signature verification failed on incoming end-to-end payload — "
                    "recipient_pubkey_path passed to with_encryption() may not match the actual sender"
                )
            payload = decrypted

        return payload, session_id
