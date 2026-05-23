from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Protocol


@dataclass(frozen=True)
class ERPClientInfo:
    id: str
    name: str
    document: str
    phone: str


@dataclass(frozen=True)
class ERPInvoice:
    id: str
    due_date: str
    amount: float
    currency: str
    status: str


@dataclass(frozen=True)
class ERPServiceTicket:
    id: str
    protocol: str
    status: str
    description: str


class ERPClient(Protocol):
    provider_name: str

    def healthcheck(self) -> bool:
        ...

    def buscar_cliente(self, document: str) -> ERPClientInfo | None:
        ...

    def listar_faturas_em_aberto(self, client_id: str) -> List[ERPInvoice]:
        ...

    def abrir_chamado(self, client_id: str, description: str) -> ERPServiceTicket:
        ...


class _BaseERPProvider:
    provider_name = "base"

    def __init__(self) -> None:
        self._clients_by_document: Dict[str, ERPClientInfo] = {
            "12345678901": ERPClientInfo(
                id=f"{self.provider_name}-c1",
                name="Maria Souza",
                document="12345678901",
                phone="5511999990001",
            )
        }
        self._invoices_by_client_id: Dict[str, List[ERPInvoice]] = {
            f"{self.provider_name}-c1": [
                ERPInvoice(
                    id=f"{self.provider_name}-inv1",
                    due_date="2026-06-10",
                    amount=149.90,
                    currency="BRL",
                    status="open",
                )
            ]
        }
        self._ticket_seq = 1

    def healthcheck(self) -> bool:
        return True

    def buscar_cliente(self, document: str) -> ERPClientInfo | None:
        return self._clients_by_document.get(document)

    def listar_faturas_em_aberto(self, client_id: str) -> List[ERPInvoice]:
        invoices = self._invoices_by_client_id.get(client_id, [])
        return [item for item in invoices if item.status == "open"]

    def abrir_chamado(self, client_id: str, description: str) -> ERPServiceTicket:
        if client_id not in self._invoices_by_client_id:
            self._invoices_by_client_id[client_id] = []
        seq = self._ticket_seq
        self._ticket_seq += 1
        return ERPServiceTicket(
            id=f"{self.provider_name}-st{seq}",
            protocol=f"{self.provider_name.upper()}-{1000 + seq}",
            status="open",
            description=description.strip(),
        )


class IXCSoftClient(_BaseERPProvider):
    provider_name = "ixcsoft"


class HubsoftClient(_BaseERPProvider):
    provider_name = "hubsoft"


class MKSolutionsClient(_BaseERPProvider):
    provider_name = "mksolutions"


class VoalleClient(_BaseERPProvider):
    provider_name = "voalle"


class SGPClient(_BaseERPProvider):
    provider_name = "sgp"


class ERPIntegrationService:
    def __init__(self, providers: Dict[str, ERPClient]) -> None:
        if not providers:
            raise ValueError("at least one ERP provider is required")
        self._providers = providers

    def healthcheck(self) -> Dict[str, bool]:
        return {name: provider.healthcheck() for name, provider in self._providers.items()}

    def buscar_cliente(self, provider_name: str, document: str) -> ERPClientInfo | None:
        provider = self._require_provider(provider_name)
        return provider.buscar_cliente(document)

    def listar_faturas_em_aberto(self, provider_name: str, client_id: str) -> List[ERPInvoice]:
        provider = self._require_provider(provider_name)
        return provider.listar_faturas_em_aberto(client_id)

    def abrir_chamado(self, provider_name: str, client_id: str, description: str) -> ERPServiceTicket:
        provider = self._require_provider(provider_name)
        return provider.abrir_chamado(client_id, description)

    def _require_provider(self, provider_name: str) -> ERPClient:
        provider = self._providers.get(provider_name)
        if provider is None:
            raise ValueError(f"provider not found: {provider_name}")
        return provider
