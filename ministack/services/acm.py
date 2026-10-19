# Copyright (c) 2026 MiniStack Contributors. SPDX-License-Identifier: MIT
# Copies or substantial portions, including AI-assisted ports or rewrites, must retain this notice (see LICENSE).
"""
ACM (Certificate Manager) Service Emulator.
JSON-based API via X-Amz-Target.
Supports: RequestCertificate, DescribeCertificate, ListCertificates,
          DeleteCertificate, GetCertificate, ImportCertificate,
          AddTagsToCertificate, RemoveTagsFromCertificate, ListTagsForCertificate,
          UpdateCertificateOptions, RenewCertificate, ResendValidationEmail,
          ExportCertificate.

With `cryptography` installed, RequestCertificate issues a real X.509
certificate for the requested names, signed by a local CA whose certificate
is the chain, and one requested with Options.Export ENABLED exports with its
private key.
"""

import base64
import copy
import datetime
import hashlib
import json
import logging
import os
import threading
import time

from ministack.core.arn import ArnParseError, parse_arn
from ministack.core.responses import (
    AccountRegionScopedDict,
    AccountScopedDict,
    error_response_json,
    get_account_id,
    get_region,
    json_response,
    new_uuid,
    now_iso,
)

logger = logging.getLogger("acm")

REGION = os.environ.get("MINISTACK_REGION", "us-east-1")

_certificates = AccountRegionScopedDict()  # arn -> certificate dict (region-scoped)
_CERTIFICATE_RESOURCE_PREFIX = "certificate/"


def get_state():
    # Strip _private_key before persisting — real AWS only exposes the
    # private key via passphrase-protected ExportCertificate, and the
    # GetCertificate path already honours that. Writing it plaintext to
    # ${STATE_DIR}/acm.json would turn warm-boot persistence into a
    # side-channel for material that the wire protocol refuses to leak.
    # The cert body and chain still round-trip; only PrivateKey is lost,
    # which means a re-import is required after restart for IMPORTED
    # certs that need the key.
    # Iterate _data directly (not items()) so the snapshot includes
    # every tenant's certificates — items() is request-scoped to the
    # current account and would silently drop other tenants' certs
    # from the persisted snapshot, breaking multi-tenancy across
    # warm boots.
    scrubbed = copy.deepcopy(_certificates)
    for cert in scrubbed._data.values():
        cert.pop("_private_key", None)
    return {"_certificates": scrubbed}


def _synthetic_pem(domain):
    """A clearly-synthetic but syntactically PEM-decodable placeholder
    for RequestCertificate-issued certs when `cryptography` is not
    installed, and so no real X.509 can be generated: anything that
    actually parses ASN.1 will still fail,
    but the PEM body must remain valid base64 so consumers that pre-
    decode (PyOpenSSL, cryptography) don't error before they get to the
    parser. The requested domain lives in DomainName / SubjectAlternative
    Names metadata, not embedded in the PEM payload.

    """
    _ = domain  # represented in cert metadata, not the base64 block
    return (
        "-----BEGIN CERTIFICATE-----\n"
        "AQIDBAUGBwgJCgsMDQ4PEA==\n"
        "-----END CERTIFICATE-----\n"
    )


# The key algorithms ACM issues a requested certificate with; the others are
# for imported certificates only.
_ISSUED_KEY_TYPES = {"RSA_2048": "rsa2048", "EC_prime256v1": "ec256", "EC_secp384r1": "ec384"}
# ACM certificates are valid for 198 days.
_ISSUED_DAYS_VALID = 198

_ca_lock = threading.Lock()
_ca: tuple[str, str] | None = None


def _issuing_ca() -> tuple[str, str]:
    """The (certificate, key) PEMs of the CA that signs requested certificates, minted on first use."""
    global _ca
    with _ca_lock:
        if _ca is None:
            from ministack.core.x509_utils import generate_ca

            _ca = generate_ca(org_name="MiniStack", common_name="MiniStack ACM Local CA")
            logger.info("ACM: generated the issuing CA")
        return _ca


def _issued_certificate(domain, sans, key_algorithm):
    """The PEM fields and validity of a certificate for *domain* and *sans*, or
    None without `cryptography`, when the synthetic placeholder stands in."""
    from ministack.core import x509_utils

    if not x509_utils.HAS_CRYPTO:
        return None
    from cryptography import x509

    ca_cert, ca_key = _issuing_ca()
    cert_pem, key_pem, _public = x509_utils.sign_leaf_certificate(
        ca_cert, ca_key, common_name=domain, san_dns=sans,
        days_valid=_ISSUED_DAYS_VALID, key_type=_ISSUED_KEY_TYPES[key_algorithm],
    )
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return {
        "NotBefore": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "NotAfter": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_pem_body": cert_pem,
        "_pem_chain": ca_cert,
        "_private_key": key_pem,
    }


def _region_from_arn(value, fallback):
    if not isinstance(value, str) or not value.startswith("arn:"):
        return fallback
    try:
        return parse_arn(value).region or fallback
    except ArnParseError:
        return fallback


def _restore_certificates(restored):
    """Region-scope certificates on restore. New state is already region-scoped;
    legacy account-scoped state is re-homed by mining the region from the
    certificate ARN key (each cert lives in exactly one region)."""
    if isinstance(restored, AccountRegionScopedDict):
        _certificates.update(restored)
        return
    boot_region = get_region()
    if isinstance(restored, AccountScopedDict):
        entries = restored._data.items()
    elif isinstance(restored, dict):
        account_id = get_account_id()
        entries = (((account_id, arn), cert) for arn, cert in restored.items())
    else:
        _certificates.update(restored)
        return
    for (account_id, arn), cert in entries:
        _certificates.set_scoped(account_id, _region_from_arn(arn, boot_region), arn, cert)


def load_persisted_state(data):
    return _restore_state(data)


def _restore_state(data):
    _restore_certificates(data.get("_certificates", {}))
    # Backwards compat: pre-fix snapshots have certificates without
    # `_pem_body` / `_pem_chain` (the old GetCertificate path returned
    # a hard-coded literal regardless of stored data). Without backfill,
    # GetCertificate would return an empty Certificate field for those
    # certs after warm-boot — strictly worse than the old behaviour.
    # Use the synthetic placeholder so consumers that just substring-
    # check 'BEGIN CERTIFICATE' (Terraform / CDK) keep working.
    for cert in _certificates._data.values():
        if "_pem_body" not in cert:
            cert["_pem_body"] = _synthetic_pem(cert.get("DomainName", ""))
        if "_pem_chain" not in cert:
            cert["_pem_chain"] = ""




def _future_iso(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def _epoch(iso_or_epoch):
    """Convert ISO timestamp to epoch float if needed. ACM API returns epoch
    floats. The seconds-only format this used to parse does not match the
    millisecond timestamps ``now_iso`` writes, so ``CreatedAt`` and
    ``IssuedAt`` fell through to the fallback and every certificate answered
    the time of the call, which made each read look like a fresh issue."""
    if isinstance(iso_or_epoch, (int, float)):
        return float(iso_or_epoch)
    try:
        return datetime.datetime.fromisoformat(
            str(iso_or_epoch).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return time.time()


def _cert_arn():
    return f"arn:aws:acm:{get_region()}:{get_account_id()}:certificate/{new_uuid()}"


def _is_local_certificate_arn(arn):
    try:
        spec = parse_arn(arn)
    except ArnParseError:
        return False
    if (
        spec.partition != "aws"
        or spec.service != "acm"
        or spec.account_id != get_account_id()
        or spec.region != get_region()
    ):
        return False
    if not spec.resource.startswith(_CERTIFICATE_RESOURCE_PREFIX):
        return False
    certificate_id = spec.resource[len(_CERTIFICATE_RESOURCE_PREFIX):]
    return bool(certificate_id) and "/" not in certificate_id


def _get_local_certificate(arn):
    if not _is_local_certificate_arn(arn):
        return None
    return _certificates.get(arn)


def _certificate_not_found(arn):
    return error_response_json("ResourceNotFoundException", f"Certificate {arn} not found", 400)


def _validation_options(domain, method):
    # A wildcard SAN validates through the same DNS record as its base domain:
    # real ACM strips the leading "*." so "*.example.com" and "example.com"
    # both resolve to a single _acme-challenge.example.com CNAME whose name AND
    # value are identical. Terraform's aws_route53_record for_each keyed by
    # domain_validation_options then collapses the two onto one record, and
    # aws_acm_certificate_validation finds the FQDN it created (#1250). The
    # value is derived from the base domain so the wildcard/apex pair match.
    base = domain[2:] if domain.startswith("*.") else domain
    digest = hashlib.sha256(base.encode("utf-8")).hexdigest()[:8]
    return {
        "DomainName": domain,
        "ValidationMethod": method,
        "ValidationStatus": "SUCCESS",
        "ResourceRecord": {
            "Name": f"_acme-challenge.{base}.",
            "Type": "CNAME",
            "Value": f"fake-validation-{digest}.acm.amazonaws.com.",
        },
    }


def _cert_shape(cert):
    return {
        "CertificateArn": cert["CertificateArn"],
        "DomainName": cert["DomainName"],
        "SubjectAlternativeNames": cert.get("SubjectAlternativeNames", [cert["DomainName"]]),
        "Status": cert["Status"],
        "Type": cert.get("Type", "AMAZON_ISSUED"),
        "KeyAlgorithm": cert.get("KeyAlgorithm", "RSA_2048"),
        "SignatureAlgorithm": "SHA256WITHRSA",
        "InUseBy": cert.get("InUseBy", []) + _signing_profiles_using(cert["CertificateArn"]),
        "CreatedAt": _epoch(cert["CreatedAt"]),
        "IssuedAt": _epoch(cert.get("IssuedAt", cert["CreatedAt"])),
        "NotBefore": _epoch(cert.get("NotBefore", cert["CreatedAt"])),
        "NotAfter": _epoch(cert.get("NotAfter", _future_iso(365 * 24 * 3600))),
        "DomainValidationOptions": cert.get("DomainValidationOptions", []),
        "Options": cert.get("Options", {}),
        "Tags": cert.get("Tags", []),
    }


async def handle_request(method, path, headers, body, query_params):
    target = headers.get("x-amz-target", "")
    action = target.split(".")[-1] if "." in target else ""

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return error_response_json("SerializationException", "Invalid JSON", 400)

    handlers = {
        "RequestCertificate": _request_certificate,
        "DescribeCertificate": _describe_certificate,
        "ListCertificates": _list_certificates,
        "DeleteCertificate": _delete_certificate,
        "GetCertificate": _get_certificate,
        "ImportCertificate": _import_certificate,
        "AddTagsToCertificate": _add_tags,
        "RemoveTagsFromCertificate": _remove_tags,
        "ListTagsForCertificate": _list_tags,
        "UpdateCertificateOptions": _update_options,
        "RenewCertificate": _renew_certificate,
        "ResendValidationEmail": _resend_validation_email,
        "ExportCertificate": _export_certificate,
    }

    handler = handlers.get(action)
    if not handler:
        return error_response_json("InvalidAction", f"Unknown action: {action}", 400)
    return handler(data)


def _request_certificate(data):
    domain = data.get("DomainName", "")
    if not domain:
        return error_response_json("InvalidParameterException", "DomainName is required", 400)
    method = data.get("ValidationMethod", "DNS")
    sans = data.get("SubjectAlternativeNames", [domain])
    if domain not in sans:
        sans = [domain] + sans
    key_algorithm = data.get("KeyAlgorithm") or "RSA_2048"
    if key_algorithm not in _ISSUED_KEY_TYPES:
        return error_response_json(
            "InvalidParameterException",
            f"KeyAlgorithm {key_algorithm} is not supported for requested certificates; "
            f"use one of {', '.join(_ISSUED_KEY_TYPES)}.", 400)
    options = data.get("Options") or {}
    arn = _cert_arn()
    now = now_iso()
    _certificates[arn] = {
        "CertificateArn": arn,
        "DomainName": domain,
        "SubjectAlternativeNames": sans,
        "Status": "ISSUED",
        "Type": "AMAZON_ISSUED",
        "CreatedAt": now,
        "IssuedAt": now,
        "NotBefore": now,
        "NotAfter": _future_iso(365 * 24 * 3600),
        "DomainValidationOptions": [_validation_options(d, method) for d in sans],
        "ValidationMethod": method,
        "KeyAlgorithm": key_algorithm,
        "Tags": data.get("Tags", []),
        # The members the request set; Export, which only the request sets, decides
        # whether the certificate exports.
        "Options": {k: options[k] for k in ("CertificateTransparencyLoggingPreference", "Export")
                    if options.get(k)},
        "_pem_body": _synthetic_pem(domain),
        "_pem_chain": "",
        "_private_key": "",
    }
    issued = _issued_certificate(domain, sans, key_algorithm)
    if issued:
        _certificates[arn].update(issued)
    logger.info("RequestCertificate: %s -> %s", domain, arn)
    return json_response({"CertificateArn": arn})


def _describe_certificate(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if not cert:
        return _certificate_not_found(arn)
    return json_response({"Certificate": _cert_shape(cert)})


def _list_certificates(data):
    statuses = data.get("CertificateStatuses", [])
    summaries = []
    for arn, cert in _certificates.items():
        if not _is_local_certificate_arn(arn):
            continue
        if statuses and cert["Status"] not in statuses:
            continue
        summaries.append({
            "CertificateArn": arn,
            "DomainName": cert["DomainName"],
            "Status": cert["Status"],
        })
    # Real AWS omits NextToken when there's no next page. boto3 strips
    # null fields client-side so it tolerates `"NextToken": null`, but
    # other SDKs (Java, Go, raw HTTP) and pagination loops checking
    # `if "NextToken" in response` see the literal null and loop
    # forever. ACM emulator currently emits a single page, so always
    # omit the key.
    return json_response({"CertificateSummaryList": summaries})


def _signing_profiles_using(arn):
    """ARNs of the Active Signer signing profiles whose signing material is this certificate."""
    from ministack.services import signer

    return [profile["arn"] for profile in signer._profiles.values()
            if profile.get("status") == "Active"
            and (profile.get("signingMaterial") or {}).get("certificateArn") == arn]


def _delete_certificate(data):
    arn = data.get("CertificateArn", "")
    if _get_local_certificate(arn) is None:
        return _certificate_not_found(arn)
    if _signing_profiles_using(arn):
        return error_response_json(
            "ResourceInUseException", f"Certificate {arn} in account {get_account_id()} is in use.", 400)
    del _certificates[arn]
    return json_response({})


def _decode_pem_field(value):
    """ImportCertificate accepts PEM bodies as base64-encoded blobs over
    the wire. boto3 base64-encodes the bytes for us; the JSON we receive
    contains the encoded string. We store the decoded UTF-8 PEM so that
    GetCertificate can return it unchanged."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        # Try base64 first (the AWS-JSON wire shape); fall back to the
        # raw string when the body is already a PEM (some SDK paths /
        # tests skip the base64 step).
        if value.lstrip().startswith("-----"):
            return value
        try:
            import base64
            return base64.b64decode(value).decode("utf-8", errors="replace")
        except Exception:
            return value
    return ""


def _get_certificate(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if cert is None:
        return _certificate_not_found(arn)
    # PrivateKey is intentionally never returned — real AWS only exposes
    # it via ExportCertificate (passphrase-protected).
    return json_response({
        "Certificate": cert.get("_pem_body", ""),
        "CertificateChain": cert.get("_pem_chain", ""),
    })


def _import_certificate(data):
    if not data.get("PrivateKey"):
        constraint = ("Member must not be null" if data.get("PrivateKey") is None
                      else "Member must have length greater than or equal to 1")
        return error_response_json(
            "ValidationException",
            f"1 validation error detected: Value at 'privateKey' failed to satisfy constraint: {constraint}", 400)
    arn = data.get("CertificateArn") or _cert_arn()
    if data.get("CertificateArn") and not _is_local_certificate_arn(arn):
        return _certificate_not_found(arn)
    now = now_iso()
    cert_body = _decode_pem_field(data.get("Certificate"))
    cert_chain = _decode_pem_field(data.get("CertificateChain"))
    private_key = _decode_pem_field(data.get("PrivateKey"))
    # Synthetic DomainName: real AWS parses CN/SAN from the cert; we
    # don't ship X.509 parsing, so we emit a clearly-synthetic value
    # that doesn't claim coverage of any specific domain. Re-import
    # preserves the existing DomainName so downstream resources stay
    # stable.
    existing = _certificates.get(arn) or {}
    domain = existing.get("DomainName") or f"imported-cert-{arn.rsplit('/', 1)[-1][:8]}.invalid"
    _certificates[arn] = {
        "CertificateArn": arn,
        "DomainName": domain,
        "SubjectAlternativeNames": existing.get("SubjectAlternativeNames", [domain]),
        "Status": "ISSUED",
        "Type": "IMPORTED",
        "CreatedAt": existing.get("CreatedAt", now),
        "IssuedAt": now,
        "NotBefore": now,
        "NotAfter": _future_iso(365 * 24 * 3600),
        "DomainValidationOptions": [],
        "Tags": data.get("Tags", existing.get("Tags", [])),
        "Options": existing.get("Options", {}),
        "_pem_body": cert_body,
        "_pem_chain": cert_chain,
        "_private_key": private_key,
    }
    return json_response({"CertificateArn": arn})


def _add_tags(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if not cert:
        return _certificate_not_found(arn)
    existing = {t["Key"]: t for t in cert.get("Tags", [])}
    for tag in data.get("Tags", []):
        existing[tag["Key"]] = tag
    cert["Tags"] = list(existing.values())
    return json_response({})


def _remove_tags(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if not cert:
        return _certificate_not_found(arn)
    remove_keys = {t["Key"] for t in data.get("Tags", [])}
    cert["Tags"] = [t for t in cert.get("Tags", []) if t["Key"] not in remove_keys]
    return json_response({})


def _list_tags(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if not cert:
        return _certificate_not_found(arn)
    return json_response({"Tags": cert.get("Tags", [])})


def _update_options(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if not cert:
        return _certificate_not_found(arn)
    cert["Options"] = data.get("Options", {})
    return json_response({})


def _renew_certificate(data):
    arn = data.get("CertificateArn", "")
    if _get_local_certificate(arn) is None:
        return _certificate_not_found(arn)
    return json_response({})


def _export_certificate(data):
    arn = data.get("CertificateArn", "")
    cert = _get_local_certificate(arn)
    if cert is None:
        return _certificate_not_found(arn)
    raw_passphrase = data.get("Passphrase")
    try:
        # A blob member, which the JSON protocol carries base64-encoded.
        passphrase = base64.b64decode(raw_passphrase) if isinstance(raw_passphrase, str) else b""
    except ValueError:
        passphrase = b""
    if raw_passphrase is None or not 4 <= len(passphrase) <= 128:
        constraint = ("Member must not be null" if raw_passphrase is None
                      else "Member must have length between 4 and 128")
        return error_response_json(
            "ValidationException",
            f"1 validation error detected: Value at 'passphrase' failed to satisfy constraint: {constraint}", 400)
    # Only a certificate ACM issued on a request with export enabled exports; a
    # placeholder issued without `cryptography`, or restored without its key, has none.
    exportable = (cert.get("Type", "AMAZON_ISSUED") == "AMAZON_ISSUED"
                  and cert.get("Options", {}).get("Export") == "ENABLED"
                  and cert.get("_private_key"))
    if not exportable:
        return error_response_json("ValidationException", f"Certificate ARN: {arn} is not exportable.", 400)
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(cert["_private_key"].encode("utf-8"), password=None)
    # Encrypted PKCS #8: cryptography writes PBES2 with 2048 PBKDF2 rounds and
    # AES-256-CBC, the scheme of the key in the ACM user guide's export example.
    private_key = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase))
    return json_response({
        "Certificate": cert["_pem_body"],
        "CertificateChain": cert.get("_pem_chain", ""),
        "PrivateKey": private_key.decode("utf-8"),
    })


def _resend_validation_email(data):
    arn = data.get("CertificateArn", "")
    if _get_local_certificate(arn) is None:
        return _certificate_not_found(arn)
    return json_response({})


def reset():
    _certificates.clear()
