"""SEO Index Checker: estado real de indexación vía Google Search Console API (urlInspection)."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from google.auth.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger("seo_checker")

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]
RETRYABLE_STATUS_CODES = {429, 500, 502, 503}


@dataclass
class IndexResult:
    url: str
    indexed: Optional[bool]
    verdict: Optional[str]
    coverage_state: Optional[str]
    last_crawl_time: Optional[str]
    status: str  # "ok" | "forbidden" | "quota_exceeded" | "error"
    checked_at: str
    detail: Optional[str] = None


class SEOIndexChecker:
    """Consulta el estado de indexación real vía Search Console (urlInspection.index.inspect).

    El motor es agnóstico a cómo se obtuvieron las credenciales: recibe un
    objeto `Credentials` ya autorizado (Service Account para uso interno,
    o las credenciales OAuth de un usuario autenticado en el SaaS).
    """

    def __init__(
        self,
        urls: list[str],
        site_url: str,
        credentials: Credentials,
        request_delay: float = 1.0,
        max_retries: int = 3,
    ):
        self.urls = urls
        self.site_url = site_url
        self.request_delay = request_delay
        self.max_retries = max_retries
        self._service = build("searchconsole", "v1", credentials=credentials, cache_discovery=False)

    @staticmethod
    def list_verified_sites(credentials: Credentials) -> list[str]:
        """Devuelve las propiedades de Search Console donde el usuario tiene acceso verificado."""
        service = build("searchconsole", "v1", credentials=credentials, cache_discovery=False)
        response = service.sites().list().execute()
        return sorted(
            entry["siteUrl"]
            for entry in response.get("siteEntry", [])
            if entry.get("permissionLevel") != "siteUnverifiedUser"
        )

    def run(self) -> dict[str, dict]:
        results: dict[str, dict] = {}
        for i, url in enumerate(self.urls):
            results[url] = asdict(self._inspect_with_retry(url))
            if i < len(self.urls) - 1:
                time.sleep(self.request_delay)
        return results

    def _inspect_with_retry(self, url: str) -> IndexResult:
        last_error: Optional[str] = None

        for attempt in range(self.max_retries + 1):
            try:
                return self._inspect_single(url)
            except HttpError as exc:
                status_code = exc.resp.status
                last_error = str(exc)

                if status_code == 403:
                    logger.error(
                        "403 en %s: el usuario no tiene acceso verificado a la propiedad '%s' en Search Console",
                        url, self.site_url,
                    )
                    return self._failed(url, "forbidden", last_error)

                if status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    backoff = (2 ** attempt) * 2
                    logger.warning("HTTP %s en %s, reintento en %ds", status_code, url, backoff)
                    time.sleep(backoff)
                    continue

                status = "quota_exceeded" if status_code == 429 else "error"
                return self._failed(url, status, last_error)
            except Exception as exc:
                last_error = repr(exc)
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                    continue
                return self._failed(url, "error", last_error)

        return self._failed(url, "error", last_error)

    def _inspect_single(self, url: str) -> IndexResult:
        body = {"inspectionUrl": url, "siteUrl": self.site_url}
        response = self._service.urlInspection().index().inspect(body=body).execute()

        index_status = response.get("inspectionResult", {}).get("indexStatusResult", {})
        verdict = index_status.get("verdict")

        return IndexResult(
            url=url,
            indexed=verdict == "PASS",
            verdict=verdict,
            coverage_state=index_status.get("coverageState"),
            last_crawl_time=index_status.get("lastCrawlTime"),
            status="ok",
            checked_at=self._now_iso(),
        )

    def _failed(self, url: str, status: str, detail: Optional[str]) -> IndexResult:
        return IndexResult(
            url=url, indexed=None, verdict=None, coverage_state=None,
            last_crawl_time=None, status=status, checked_at=self._now_iso(), detail=detail,
        )

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()


def save_results(results: dict[str, dict], path: str = "index_results.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


def _main() -> None:
    """Prueba manual por CLI usando una Service Account (no usado por el SaaS/app.py)."""
    from google.oauth2 import service_account as service_account_module

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    credentials = service_account_module.Credentials.from_service_account_file(
        "credenciales.json", scopes=SCOPES
    )

    urls = ["https://jm7997.github.io/SEO-Index-Checker-MVP/"]

    checker = SEOIndexChecker(
        urls=urls,
        site_url="https://jm7997.github.io/SEO-Index-Checker-MVP/",
        credentials=credentials,
        request_delay=1.0,
    )
    results = checker.run()

    print(json.dumps(results, ensure_ascii=False, indent=2))
    save_results(results)


if __name__ == "__main__":
    _main()
