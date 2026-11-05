from django import forms
from .features import normalize_url
class WebsiteScanForm(forms.Form):
    url = forms.CharField(label="Website URL", max_length=2048, widget=forms.TextInput(attrs={"placeholder": "https://www.hackerrank.com/", "class": "form-control", "autocomplete": "off"}))
    check_reputation = forms.BooleanField(required=False, label="Also check Google Safe Browsing (sends this URL to Google; requires an API key)")
    def clean_url(self):
        try:
            return normalize_url(self.cleaned_data["url"])
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc
