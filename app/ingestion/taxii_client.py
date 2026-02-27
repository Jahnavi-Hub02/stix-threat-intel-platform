"""
TAXII 2.1 Client for Threat Intelligence Feed Ingestion
========================================================

Features:
- Multiple authentication methods (API key, username/password, no-auth)
- Connection error handling with 3-retry exponential backoff
- Delta ingestion (only new objects since last run)
- Automatic pagination following 'next' links
- Multi-collection support (loops all collections)
- Multiple IOC types (IPv4, domain, URL, SHA-256, MD5)
- Audit logging to ingestion_logs table
- Pre-configured public TAXII servers (Anomali Limo, CISA AIS)

Usage:
    from app.ingestion.taxii_client import TAXIIClient
    
    client = TAXIIClient(
        server_url="https://limo.anomali.com/api/v1/taxii2/taxii/",
        username="guest",
        password="guest"
    )
    result = client.ingest_all_collections()
"""

import re
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from app.database import insert_indicators
from app.utils.logger import get_logger
from app.database.db_manager import create_connection

logger = get_logger(__name__)


# Pre-configured public TAXII servers
PUBLIC_SERVERS = {
    "anomali_limo": {
        "url": "https://limo.anomali.com/api/v1/taxii2/taxii/",
        "username": "guest",
        "password": "guest",
        "description": "Anomali Limo - Free threat intelligence",
    },
    "cisa_ais": {
        "url": "https://ais.cisa.dhs.gov/taxii2/taxii2/",
        "username": None,
        "password": None,
        "description": "CISA - Automated Indicator Sharing",
    },
}


class TAXIIClient:
    """TAXII 2.1 client for fetching and parsing threat intelligence."""

    def __init__(
        self,
        server_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        """
        Initialize TAXII client.

        Args:
            server_url: Base URL of TAXII server (e.g., https://taxii.server.com/api/v2/)
            username: Username for basic auth
            password: Password for basic auth
            api_key: API key for header-based auth
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()

        # Retry strategy: 3 retries with exponential backoff
        retry = Retry(
            total=3,
            backoff_factor=2,  # 2s, 4s, 8s
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )

        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set authentication
        if self.username and self.password:
            session.auth = (self.username, self.password)
        elif self.api_key:
            session.headers.update({"X-APIKey": self.api_key})

        return session

    def get_taxii_root(self) -> Dict:
        """Fetch TAXII API root."""
        try:
            logger.info("Fetching TAXII root", url=self.server_url)
            response = self.session.get(
                self.server_url,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error", error=str(e))
            raise
        except requests.exceptions.Timeout as e:
            logger.error("Request timeout", error=str(e))
            raise
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                logger.error("Authentication failed (401)")
            elif response.status_code == 403:
                logger.error("Access forbidden (403)")
            elif response.status_code == 404:
                logger.error("Server not found (404)")
            raise

    def get_collections(self) -> List[Dict]:
        """Fetch all available collections."""
        try:
            root = self.get_taxii_root()
            collections_url = root.get("collections")

            if not collections_url:
                logger.warning("No collections endpoint found")
                return []

            # Build full URL if relative
            if collections_url.startswith("/"):
                collections_url = self.server_url.rstrip("/") + collections_url
            elif not collections_url.startswith("http"):
                collections_url = self.server_url + collections_url

            logger.info("Fetching collections", url=collections_url)
            response = self.session.get(
                collections_url,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            response.raise_for_status()

            data = response.json()
            collections = data.get("collections", [])
            logger.info("Collections retrieved", count=len(collections))
            return collections

        except Exception as e:
            logger.error("Failed to get collections", error=str(e))
            return []

    def fetch_collection_objects(
        self,
        collection_url: str,
        use_delta: bool = True,
        max_objects: Optional[int] = None,
    ) -> List[Dict]:
        """
        Fetch objects from a collection with pagination support.

        Args:
            collection_url: URL to the collection objects endpoint
            use_delta: If True, only fetch objects modified since last run
            max_objects: Maximum number of objects to fetch (None = unlimited)

        Returns:
            List of STIX objects
        """
        objects = []
        params = {}

        # Delta ingestion: only fetch new/modified objects
        if use_delta:
            last_timestamp = self._get_last_ingestion_timestamp()
            if last_timestamp:
                params["added_after"] = last_timestamp  # ISO 8601 format
                logger.info("Delta ingestion enabled", since=last_timestamp)

        current_url = collection_url
        fetched_count = 0

        while current_url and (max_objects is None or fetched_count < max_objects):
            try:
                logger.info("Fetching objects", url=current_url)
                response = self.session.get(
                    current_url,
                    params=params if current_url == collection_url else {},
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
                response.raise_for_status()

                data = response.json()
                batch = data.get("objects", [])
                objects.extend(batch)
                fetched_count += len(batch)

                logger.info(
                    "Objects fetched",
                    batch_size=len(batch),
                    total=len(objects),
                )

                # Check for pagination (next link)
                current_url = None
                if "next" in response.links:
                    current_url = response.links["next"]["url"]
                    logger.info("Following pagination", next_url=current_url)

                # Respect max_objects limit
                if max_objects and fetched_count >= max_objects:
                    logger.info("Max objects reached", limit=max_objects)
                    break

            except Exception as e:
                logger.error("Failed to fetch collection objects", error=str(e))
                break

        return objects[:max_objects] if max_objects else objects

    def parse_stix_object(self, stix_obj: Dict) -> Optional[Dict]:
        """
        Parse a STIX indicator object and extract IOC.

        Supports:
        - IPv4 addresses
        - Domain names
        - URLs
        - File hashes (SHA-256, MD5)
        """
        if stix_obj.get("type") != "indicator":
            return None

        pattern = stix_obj.get("pattern", "")
        if not pattern:
            return None

        # IPv4: [ipv4-addr:value = '192.168.1.1']
        ipv4_match = re.search(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", pattern)
        if ipv4_match:
            ip = ipv4_match.group(1).strip()
            if self._is_valid_ipv4(ip):
                return {
                    "stix_id": stix_obj.get("id"),
                    "ioc_type": "ipv4",
                    "ioc_value": ip,
                    "confidence": stix_obj.get("confidence", 50),
                    "source": "TAXII",
                }

        # Domain: [domain-name:value = 'example.com']
        domain_match = re.search(
            r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern
        )
        if domain_match:
            domain = domain_match.group(1).strip().lower()
            return {
                "stix_id": stix_obj.get("id"),
                "ioc_type": "domain",
                "ioc_value": domain,
                "confidence": stix_obj.get("confidence", 50),
                "source": "TAXII",
            }

        # URL: [url:value = 'http://example.com/malware']
        url_match = re.search(r"\[url:value\s*=\s*'([^']+)'\]", pattern)
        if url_match:
            url = url_match.group(1).strip()
            return {
                "stix_id": stix_obj.get("id"),
                "ioc_type": "url",
                "ioc_value": url,
                "confidence": stix_obj.get("confidence", 50),
                "source": "TAXII",
            }

        # SHA-256: [file:hashes.SHA-256 = 'hash']
        sha256_match = re.search(
            r"\[file:hashes\.SHA-256\s*=\s*'([^']+)'\]", pattern
        )
        if sha256_match:
            hash_val = sha256_match.group(1).strip().upper()
            if len(hash_val) == 64:  # SHA-256 is 64 chars
                return {
                    "stix_id": stix_obj.get("id"),
                    "ioc_type": "sha256",
                    "ioc_value": hash_val,
                    "confidence": stix_obj.get("confidence", 50),
                    "source": "TAXII",
                }

        # MD5: [file:hashes.MD5 = 'hash']
        md5_match = re.search(r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", pattern)
        if md5_match:
            hash_val = md5_match.group(1).strip().upper()
            if len(hash_val) == 32:  # MD5 is 32 chars
                return {
                    "stix_id": stix_obj.get("id"),
                    "ioc_type": "md5",
                    "ioc_value": hash_val,
                    "confidence": stix_obj.get("confidence", 50),
                    "source": "TAXII",
                }

        return None

    def ingest_all_collections(
        self, use_delta: bool = True, max_objects_per_collection: Optional[int] = None
    ) -> Dict:
        """
        Ingest indicators from all collections.

        Returns:
            Dict with ingestion results {total_fetched, total_stored, duplicates}
        """
        total_fetched = 0
        total_stored = 0
        total_duplicates = 0

        try:
            collections = self.get_collections()

            if not collections:
                logger.warning("No collections available")
                return {
                    "total_fetched": 0,
                    "total_stored": 0,
                    "duplicates": 0,
                }

            for collection in collections:
                collection_id = collection.get("id", "unknown")
                collection_url = collection.get("url", "")

                if not collection_url:
                    logger.warning("No URL for collection", id=collection_id)
                    continue

                logger.info("Processing collection", id=collection_id)

                # Fetch objects
                stix_objects = self.fetch_collection_objects(
                    collection_url,
                    use_delta=use_delta,
                    max_objects=max_objects_per_collection,
                )

                # Parse into IOCs
                indicators = []
                for stix_obj in stix_objects:
                    ioc = self.parse_stix_object(stix_obj)
                    if ioc:
                        indicators.append(ioc)

                # Store in database
                if indicators:
                    result = insert_indicators(indicators)
                    total_fetched += len(stix_objects)
                    total_stored += result.get("stored", 0)
                    total_duplicates += result.get("duplicates", 0)
                    logger.info(
                        "Collection ingested",
                        id=collection_id,
                        stored=result.get("stored"),
                        duplicates=result.get("duplicates"),
                    )

            return {
                "total_fetched": total_fetched,
                "total_stored": total_stored,
                "duplicates": total_duplicates,
            }

        except Exception as e:
            logger.error("Ingestion failed", error=str(e))
            raise

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        """Validate IPv4 address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def _get_last_ingestion_timestamp() -> Optional[str]:
        """Get the timestamp of the last successful ingestion."""
        try:
            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(completed_at) FROM ingestion_logs WHERE status = 'success'"
            )
            result = cursor.fetchone()
            conn.close()

            if result and result[0]:
                # Return ISO 8601 format
                return result[0]
            return None
        except Exception as e:
            logger.error("Failed to get last ingestion timestamp", error=str(e))
            return None
