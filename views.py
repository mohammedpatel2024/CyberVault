import logging
from urllib.parse import urlsplit
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from .forms import WebsiteScanForm
from .models import WebsiteScan
from .features import extract_url_features
from .services import dns_analysis, check_tls, assess_risk, ScanError
from .ml_predictor import predict_phishing
from .reputation import check_reputation

logger = logging.getLogger(__name__)
@require_http_methods(["GET", "POST"])
def scanner(request):
    form = WebsiteScanForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        url = form.cleaned_data["url"]
        host = urlsplit(url).hostname
        try:
            addresses, records = dns_analysis(host)
        except ScanError as exc:
            form.add_error("url", str(exc))
        else:
            network_ready = records.get("network_checks", {}).get("status") != "Skipped: incomplete address resolution"
            tls_status, tls_details = check_tls(host, addresses[0]) if network_ready else ("Not checked", {"message": "Address resolution was incomplete; TLS connection skipped."})
            features = extract_url_features(url)
            probability, version, model_status = None, "", "Available"
            try:
                probability, version = predict_phishing(url)
            except FileNotFoundError:
                model_status = "Model unavailable. Train the URL model to enable predictions."
            except Exception:
                logger.warning("Unable to run local phishing model", exc_info=True)
                model_status = "Model could not be loaded. Retrain it with the installed dependencies."
            reputation, reputation_details = check_reputation(url, form.cleaned_data["check_reputation"])
            score, level, reasons = assess_risk(features, probability, tls_status, reputation)
            scan = WebsiteScan.objects.create(url=url, domain=host, ip_addresses=addresses, dns_records=records, tls_status=tls_status, tls_details=tls_details, url_features=features, phishing_probability=probability, model_status=model_status, model_version=version, reputation_status=reputation, reputation_details=reputation_details, risk_score=score, risk_level=level, explanations=reasons)
            request.session["last_website_scan_id"] = scan.pk
            return redirect("website_scanner")
    result = WebsiteScan.objects.filter(pk=(request.GET.get("scan") if request.GET.get("scan", "").isascii() and request.GET.get("scan", "").isdigit() and len(request.GET.get("scan", "")) <= 18 else request.session.get("last_website_scan_id"))).first() if request.method == "GET" else None
    return render(request, "website_scanner/scanner.html", {"form": form, "result": result, "history": WebsiteScan.objects.all()[:10]})
