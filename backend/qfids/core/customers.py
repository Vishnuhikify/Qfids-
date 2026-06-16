"""
customers.py — Customer accounts & channel subscriptions for the customer portal.

The operator dashboard sees ALL channels. A *customer* should see only the
channels they have purchased / subscribed to. This module provides:

  - a simple customer registry (id, name, company, plan, API token)
  - a mapping of which channels each customer owns
  - plan tiers (Starter / Business / Enterprise) that gate features
  - token-based lookup for authenticating portal requests

This is intentionally lightweight (in-memory) — appropriate for a demo — but the
API shape matches what a real multi-tenant SaaS would use, so it could be backed
by a database without changing the routes.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Optional


# ── Plan definitions ──────────────────────────────────────────────────────
PLANS = {
    "starter": {
        "name": "Starter",
        "max_channels": 1,
        "price_inr_month": 4999,
        "features": ["Live monitoring", "Email alerts", "7-day log retention"],
        "encryption": "HQNN single-layer",
        "support": "Email (48h)",
    },
    "business": {
        "name": "Business",
        "max_channels": 2,
        "price_inr_month": 14999,
        "features": ["Live monitoring", "Quantum honeypot", "Adaptive threshold",
                     "30-day log retention", "Incident reports"],
        "encryption": "HQNN double-layer",
        "support": "Email + chat (12h)",
    },
    "enterprise": {
        "name": "Enterprise",
        "max_channels": 4,
        "price_inr_month": 49999,
        "features": ["Everything in Business", "Decoy-state QKD protection",
                     "MITM channel authentication", "Cross-channel correlation",
                     "MITRE ATT&CK mapping", "Unlimited log retention",
                     "Dedicated SOC analyst"],
        "encryption": "HQNN double-layer + forward secrecy",
        "support": "24/7 phone + dedicated analyst",
    },
}


@dataclass
class Customer:
    customer_id: str
    name: str
    company: str
    email: str
    plan: str                       # 'starter' | 'business' | 'enterprise'
    token: str
    channels: list[str] = field(default_factory=list)   # subscribed channel ids
    created_at: float = field(default_factory=time.time)

    def public_dict(self) -> dict:
        """Customer info WITHOUT the secret token."""
        plan = PLANS.get(self.plan, PLANS["starter"])
        return {
            "customer_id": self.customer_id,
            "name": self.name,
            "company": self.company,
            "email": self.email,
            "plan": self.plan,
            "plan_details": plan,
            "channels": self.channels,
            "channel_count": len(self.channels),
            "created_at": self.created_at,
        }


class CustomerRegistry:
    """In-memory customer store with token lookup."""

    def __init__(self):
        self._by_id: dict[str, Customer] = {}
        self._by_token: dict[str, str] = {}   # token → customer_id
        self._seed()

    def _seed(self):
        """
        Seed a few demo customers so the portal is immediately usable.
        Tokens are deterministic for the demo so they can be shared easily.
        Channel ids match the operator side (ch-a .. ch-d).
        """
        demo = [
            Customer(
                customer_id="cust-001",
                name="Aarav Mehta",
                company="Meridian Bank",
                email="aarav@meridianbank.example",
                plan="enterprise",
                token="demo-enterprise-token",
                channels=["ch-a", "ch-b", "ch-c", "ch-d"],
            ),
            Customer(
                customer_id="cust-002",
                name="Priya Nair",
                company="Helix Telecom",
                email="priya@helixtelecom.example",
                plan="business",
                token="demo-business-token",
                channels=["ch-b", "ch-c"],
            ),
            Customer(
                customer_id="cust-003",
                name="Rohan Gupta",
                company="Nimbus Fintech",
                email="rohan@nimbus.example",
                plan="starter",
                token="demo-starter-token",
                channels=["ch-a"],
            ),
        ]
        for c in demo:
            self._by_id[c.customer_id] = c
            self._by_token[c.token] = c.customer_id

    def authenticate(self, token: str) -> Optional[Customer]:
        cid = self._by_token.get(token)
        return self._by_id.get(cid) if cid else None

    def by_email(self, email: str) -> Optional[Customer]:
        for c in self._by_id.values():
            if c.email.lower() == email.lower():
                return c
        return None

    def get(self, customer_id: str) -> Optional[Customer]:
        return self._by_id.get(customer_id)

    def all(self) -> list[Customer]:
        return list(self._by_id.values())

    def create(self, name: str, company: str, email: str, plan: str,
               channels: list[str]) -> Customer:
        cid = f"cust-{len(self._by_id) + 1:03d}"
        token = secrets.token_urlsafe(24)
        c = Customer(customer_id=cid, name=name, company=company, email=email,
                     plan=plan, token=token, channels=channels)
        self._by_id[cid] = c
        self._by_token[token] = cid
        return c

    def update_channels(self, customer_id: str, channels: list[str]) -> Optional[Customer]:
        c = self._by_id.get(customer_id)
        if c is None:
            return None
        # Enforce plan channel limit
        limit = PLANS.get(c.plan, PLANS["starter"])["max_channels"]
        c.channels = channels[:limit]
        return c


# Module singleton
_registry = CustomerRegistry()


def get_registry() -> CustomerRegistry:
    return _registry


def list_plans() -> dict:
    return PLANS


def public_from_doc(doc: dict) -> dict:
    """
    Format a Firestore customer document into the same public shape that
    Customer.public_dict() returns, so the frontend is agnostic to the store.
    """
    plan_id = doc.get("plan", "starter")
    plan = PLANS.get(plan_id, PLANS["starter"])
    channels = doc.get("channels", []) or []
    return {
        "customer_id": doc.get("customer_id") or doc.get("uid"),
        "name": doc.get("name", ""),
        "company": doc.get("company", ""),
        "email": doc.get("email", ""),
        "plan": plan_id,
        "plan_details": plan,
        "channels": channels,
        "channel_count": len(channels),
        "created_at": doc.get("created_at"),
    }
