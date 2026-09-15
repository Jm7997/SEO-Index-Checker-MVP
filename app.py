"""SEO Index Checker PRO: SaaS con Sign in with Google (OAuth 2.0) sobre Search Console."""

from __future__ import annotations

import hmac
import os
import secrets
import time
from hashlib import sha256

import pandas as pd
import streamlit as st
from google_auth_oauthlib.flow import Flow

from seo_checker import SEOIndexChecker

st.set_page_config(page_title="SEO Index Checker PRO", page_icon="🔍", layout="wide")

SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]
INDEXED_LABELS = {True: "✅ Sí", False: "❌ No", None: "⚠️ Desconocido"}

_REDIRECT_URI = st.secrets.get("google_oauth", {}).get("redirect_uri", "")
if _REDIRECT_URI.startswith(("http://localhost", "http://127.0.0.1")):
    # oauthlib exige HTTPS por defecto; en local sobre http lo relajamos explícitamente.
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

_STATE_MAX_AGE_SECONDS = 600


def _client_secret_key() -> bytes:
    return st.secrets["google_oauth"]["client_secret"].encode()


def _new_oauth_state() -> str:
    """Genera un `state` OAuth autoverificable (HMAC + timestamp + nonce), sin
    depender de st.session_state: el navegador hace una navegación completa de
    ida y vuelta a Google, y Streamlit abre una sesión nueva en cada carga de
    página completa, así que nada guardado en session_state antes del redirect
    sigue disponible al volver."""
    payload = f"{int(time.time())}.{secrets.token_urlsafe(16)}"
    signature = hmac.new(_client_secret_key(), payload.encode(), sha256).hexdigest()
    return f"{payload}.{signature}"


def _verify_oauth_state(state: str) -> bool:
    parts = state.split(".")
    if len(parts) != 3:
        return False
    timestamp, nonce, signature = parts
    payload = f"{timestamp}.{nonce}"
    expected = hmac.new(_client_secret_key(), payload.encode(), sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    return (time.time() - int(timestamp)) <= _STATE_MAX_AGE_SECONDS


def _code_verifier_for_state(state: str) -> str:
    """Deriva el code_verifier PKCE de forma determinista a partir del `state` ya
    verificado (Google lo devuelve intacto en el callback), en vez de guardar
    `flow.code_verifier` en session_state: por la misma razón que el `state`, no
    sobreviviría al redirect. Un HMAC-SHA256 en hexadecimal (64 chars, alfabeto
    [0-9a-f]) cumple el charset y la longitud (43-128) que exige PKCE."""
    return hmac.new(_client_secret_key(), f"pkce:{state}".encode(), sha256).hexdigest()


def get_client_config() -> dict:
    oauth = st.secrets["google_oauth"]
    return {
        "web": {
            "client_id": oauth["client_id"],
            "client_secret": oauth["client_secret"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [oauth["redirect_uri"]],
        }
    }


def build_flow(code_verifier: str) -> Flow:
    return Flow.from_client_config(
        get_client_config(),
        scopes=SCOPES,
        redirect_uri=st.secrets["google_oauth"]["redirect_uri"],
        code_verifier=code_verifier,
    )


def handle_oauth_callback() -> bool:
    """Si Google acaba de redirigir con un `code`, lo intercambia por credenciales."""
    params = st.query_params
    if "code" not in params:
        return False

    state = params.get("state", "")
    if not _verify_oauth_state(state):
        st.error("El estado OAuth no es válido o ha caducado. Vuelve a iniciar sesión.")
        st.query_params.clear()
        return False

    try:
        flow = build_flow(code_verifier=_code_verifier_for_state(state))
        flow.fetch_token(code=params["code"])
    except Exception as exc:
        st.error(f"No se pudo completar el inicio de sesión con Google: {exc}")
        st.query_params.clear()
        return False

    st.session_state.credentials = flow.credentials
    st.query_params.clear()
    return True


def login_screen() -> None:
    st.title("SEO Index Checker PRO")
    st.caption("Auditoría de indexación masiva con la API oficial de Google")
    st.divider()
    st.write("Inicia sesión con tu cuenta de Google para auditar las propiedades de tu Search Console.")

    state = _new_oauth_state()
    flow = build_flow(code_verifier=_code_verifier_for_state(state))
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    # target="_top" (no "_self", no st.link_button): Streamlit Cloud sirve la app
    # dentro de un iframe propio. "_self" navegaría ese iframe, y Google bloquea
    # su pantalla de login si detecta que se carga enmarcada (anti-clickjacking),
    # de ahí el 403. "_top" rompe el iframe y navega la pestaña real.
    st.markdown(
        f'<a href="{auth_url}" target="_top" style="display:inline-block;'
        "padding:0.55rem 1.1rem;background-color:#4285F4;color:#ffffff;"
        'border-radius:0.5rem;text-decoration:none;font-weight:600;">'
        "🔐 Iniciar sesión con Google</a>",
        unsafe_allow_html=True,
    )


def parse_urls(raw_text: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for line in raw_text.splitlines():
        url = line.strip()
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def build_dataframe(results: dict[str, dict]) -> pd.DataFrame:
    rows = []
    for url, r in results.items():
        if r["status"] == "ok":
            detail = r["coverage_state"] or r["verdict"] or "—"
        else:
            detail = f"{r['status']}: {r['detail']}" if r["detail"] else r["status"]

        rows.append(
            {
                "URL": url,
                "Estado de Indexación": INDEXED_LABELS[r["indexed"]],
                "Detalle": detail,
            }
        )
    return pd.DataFrame(rows)


def main_app() -> None:
    credentials = st.session_state.credentials

    header_col, logout_col = st.columns([5, 1])
    with header_col:
        st.title("SEO Index Checker PRO")
        st.caption("Auditoría de indexación masiva con la API oficial de Google")
    with logout_col:
        if st.button("Cerrar sesión"):
            st.session_state.pop("credentials", None)
            st.rerun()

    try:
        sites = SEOIndexChecker.list_verified_sites(credentials)
    except Exception as exc:
        st.error(f"No se pudieron listar tus propiedades de Search Console: {exc}")
        return

    if not sites:
        st.warning(
            "Tu cuenta de Google no tiene ninguna propiedad verificada en Search Console. "
            "Añade y verifica un sitio en https://search.google.com/search-console antes de continuar."
        )
        return

    site_url = st.selectbox("Propiedad de Search Console a auditar", sites)

    urls_raw = st.text_area(
        "URLs a comprobar (una por línea)",
        height=220,
        placeholder="https://tudominio.com/pagina-1\nhttps://tudominio.com/pagina-2",
    )

    if st.button("Comprobar Indexación", type="primary"):
        urls = parse_urls(urls_raw)

        if not urls:
            st.error("Pega al menos una URL para comprobar.")
            return

        with st.spinner(f"Consultando el estado de indexación de {len(urls)} URL(s) en Google..."):
            checker = SEOIndexChecker(urls=urls, site_url=site_url, credentials=credentials)
            results = checker.run()

        df = build_dataframe(results)
        indexed_count = sum(1 for r in results.values() if r["indexed"] is True)

        col1, col2, col3 = st.columns(3)
        col1.metric("URLs comprobadas", len(results))
        col2.metric("Indexadas", indexed_count)
        col3.metric("No indexadas / desconocidas", len(results) - indexed_count)

        st.dataframe(df, use_container_width=True, hide_index=True)

        st.download_button(
            "Descargar resultados (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="index_results.csv",
            mime="text/csv",
        )


if "credentials" not in st.session_state:
    handle_oauth_callback()

if "credentials" not in st.session_state:
    login_screen()
else:
    main_app()
