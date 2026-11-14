"""
Deterministic stand-in for the live Valio Aimo API (availability + price).

Used when no VALIO_API_KEY is configured or GATEWAY_UPSTREAM=mock. It builds
raw responses in the *exact* live contract shape and passes them through the
same normalizers as ValioApiClient, so the gateway's zero-trust parsing is
exercised end to end.

* Prices are a stable function of the product id and its content per sales unit.
* MOCK_OUT_OF_STOCK=id1,id2 (or .out_of_stock at runtime) simulates stock-outs.
* .price_drift_pct[pid] = 15 simulates a price change between quote and order.
"""

from __future__ import annotations

import hashlib
import os
from datetime import date, datetime, timezone
from typing import Sequence

from .data_adapter import AvailabilityRecord, PriceRecord, ProductCatalog, ValioApiClient

_VAT = {"STANDARD": 25.5, "MEDIUM": 13.5, "LOW": 10.0}


def _unit(pid: str) -> float:
    return int(hashlib.sha256(pid.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


class MockValioApi:
    def __init__(self, catalog: ProductCatalog, out_of_stock: Sequence[str] = (),
                 default_stock: float = 5000.0) -> None:
        self.catalog = catalog
        env = [s.strip() for s in os.getenv("MOCK_OUT_OF_STOCK", "").split(",") if s.strip()]
        self.out_of_stock: set[str] = set(out_of_stock) | set(env)
        self.price_drift_pct: dict[str, float] = {}
        self.default_stock = default_stock
        self.mode = "mock"

    @staticmethod
    def _date(d: date | str) -> str:
        s = d.isoformat() if isinstance(d, date) else str(d)
        date.fromisoformat(s)
        return s

    async def availability(self, customer: str, requested_date: date | str,
                           product_ids: Sequence[str]) -> dict[str, AvailabilityRecord]:
        req = self._date(requested_date)
        out: dict[str, AvailabilityRecord] = {}
        for pid in dict.fromkeys(map(str, product_ids)):
            p = self.catalog.get(pid)
            if p is None:
                out[pid] = AvailabilityRecord(pid, "UNKNOWN", True, 0.0, None, None, None, None, {})
                continue
            lines = [] if pid in self.out_of_stock else [{
                "salesBlock": False, "availableAmount": self.default_stock,
                "availableDate": req, "salesUnit": p.sales_unit or "ST",
            }]
            raw = {"productId": pid, "closingTime": f"{req}T10:00:00+02:00", "salesBlock": False,
                   "logisticModel": "MOCK", "scheduleLines": lines}
            out[pid] = ValioApiClient._normalize_availability(raw, req)
        return out

    async def price(self, customer: str, requested_date: date | str,
                    product_ids: Sequence[str]) -> dict[str, PriceRecord]:
        req = self._date(requested_date)
        out: dict[str, PriceRecord] = {}
        for pid in dict.fromkeys(map(str, product_ids)):
            p = self.catalog.get(pid)
            if p is None:
                out[pid] = PriceRecord(pid, "UNKNOWN", None, None, None, None, False, None, None, None, None, {})
                continue
            u = _unit(pid)
            content = p.content_per_sales_unit
            value = (0.9 + 2.6 * u) * content if content else 2.0 + 30.0 * u
            value = round(value * (1 + self.price_drift_pct.get(pid, 0.0) / 100), 2)
            rate = _VAT.get(p.vat_code or "", 14.0)
            with_tax = round(value * (1 + rate / 100), 2)
            raw = {
                "productId": pid, "quantity": 1,
                "catalogPrice": {"value": value, "valueWithTax": with_tax, "validFrom": req,
                                 "validTo": req, "currency": "EUR"},
                "priceWithTax": {"value": with_tax, "validFrom": req, "validTo": req, "currency": "EUR"},
                "comparisonPrice": None, "comparisonUnit": None,
                "tax": {"taxRate": rate, "taxValue": round(with_tax - value, 2)},
                "listPrice": None, "netPriceFound": True, "error": False,
            }
            out[pid] = ValioApiClient._normalize_price(raw)
        return out

    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()
