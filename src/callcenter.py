from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional
import re


ALLOWED_STATUS = {"open", "pending", "resolved"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"\D+", "", phone or "")
    if not digits:
        raise ValueError("phone is required")
    return digits


@dataclass(frozen=True)
class Contact:
    id: int
    name: str
    phone: str
    created_at: datetime


@dataclass
class Ticket:
    id: int
    contact_id: int
    queue: str
    agent: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class Message:
    id: int
    ticket_id: int
    sender: str  # "agent" | "customer"
    text: str
    created_at: datetime


@dataclass(frozen=True)
class ConversationRecord:
    ticket: Ticket
    messages: List[Message]
    last_activity_at: datetime


class CallCenter:
    def __init__(self) -> None:
        self._contacts: Dict[int, Contact] = {}
        self._contacts_by_phone: Dict[str, int] = {}
        self._tickets: Dict[int, Ticket] = {}
        self._messages: Dict[int, List[Message]] = {}
        self._next_contact_id = 1
        self._next_ticket_id = 1
        self._next_message_id = 1

    def create_contact(self, name: str, phone: str) -> Contact:
        name = (name or "").strip()
        if not name:
            raise ValueError("name is required")
        normalized_phone = normalize_phone(phone)

        existing_id = self._contacts_by_phone.get(normalized_phone)
        if existing_id is not None:
            return self._contacts[existing_id]

        contact = Contact(
            id=self._next_contact_id,
            name=name,
            phone=normalized_phone,
            created_at=_utc_now(),
        )
        self._contacts[contact.id] = contact
        self._contacts_by_phone[contact.phone] = contact.id
        self._next_contact_id += 1
        return contact

    def open_ticket(self, contact_id: int, queue: str, agent: Optional[str] = None) -> Ticket:
        if contact_id not in self._contacts:
            raise ValueError("contact not found")
        queue = (queue or "").strip()
        if not queue:
            raise ValueError("queue is required")

        now = _utc_now()
        ticket = Ticket(
            id=self._next_ticket_id,
            contact_id=contact_id,
            queue=queue,
            agent=(agent or "").strip() or None,
            status="open",
            created_at=now,
            updated_at=now,
        )
        self._tickets[ticket.id] = ticket
        self._messages[ticket.id] = []
        self._next_ticket_id += 1
        return ticket

    def assign_ticket(self, ticket_id: int, agent: str) -> Ticket:
        ticket = self._require_ticket(ticket_id)
        agent = (agent or "").strip()
        if not agent:
            raise ValueError("agent is required")
        ticket.agent = agent
        ticket.updated_at = _utc_now()
        return ticket

    def change_status(self, ticket_id: int, status: str) -> Ticket:
        ticket = self._require_ticket(ticket_id)
        if status not in ALLOWED_STATUS:
            raise ValueError(f"invalid status: {status}")
        ticket.status = status
        ticket.updated_at = _utc_now()
        return ticket

    def add_message(self, ticket_id: int, sender: str, text: str) -> Message:
        ticket = self._require_ticket(ticket_id)
        sender = (sender or "").strip().lower()
        if sender not in {"agent", "customer"}:
            raise ValueError("sender must be 'agent' or 'customer'")
        text = (text or "").strip()
        if not text:
            raise ValueError("text is required")

        # Business rule: a customer reply on a resolved ticket reopens to pending.
        if sender == "customer" and ticket.status == "resolved":
            ticket.status = "pending"

        ticket.updated_at = _utc_now()
        message = Message(
            id=self._next_message_id,
            ticket_id=ticket_id,
            sender=sender,
            text=text,
            created_at=ticket.updated_at,
        )
        self._messages[ticket_id].append(message)
        self._next_message_id += 1
        return message

    def list_tickets(self, status: Optional[str] = None, queue: Optional[str] = None) -> List[Ticket]:
        items = list(self._tickets.values())
        if status is not None:
            if status not in ALLOWED_STATUS:
                raise ValueError(f"invalid status: {status}")
            items = [t for t in items if t.status == status]
        if queue is not None:
            queue = queue.strip()
            items = [t for t in items if t.queue == queue]
        return sorted(items, key=lambda t: t.id)

    def list_messages(self, ticket_id: int) -> List[Message]:
        self._require_ticket(ticket_id)
        return list(self._messages[ticket_id])

    def get_metrics(self) -> dict:
        summary = {"open": 0, "pending": 0, "resolved": 0}
        for ticket in self._tickets.values():
            summary[ticket.status] += 1

        total_messages = sum(len(items) for items in self._messages.values())
        return {
            "contacts": len(self._contacts),
            "tickets": len(self._tickets),
            "messages": total_messages,
            "status_summary": summary,
        }

    def _require_ticket(self, ticket_id: int) -> Ticket:
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise ValueError("ticket not found")
        return ticket

    def _require_contact(self, contact_id: int) -> Contact:
        contact = self._contacts.get(contact_id)
        if contact is None:
            raise ValueError("contact not found")
        return contact

    def _list_conversations_by_contact(self, contact_id: int) -> List[ConversationRecord]:
        self._require_contact(contact_id)
        records: List[ConversationRecord] = []
        for ticket in self._tickets.values():
            if ticket.contact_id != contact_id:
                continue
            messages = list(self._messages.get(ticket.id, []))
            last_activity_at = messages[-1].created_at if messages else ticket.updated_at
            records.append(
                ConversationRecord(
                    ticket=ticket,
                    messages=messages,
                    last_activity_at=last_activity_at,
                )
            )
        return records


class AtendimentoService:
    def __init__(self, callcenter: CallCenter) -> None:
        self._callcenter = callcenter

    def registrar_conversa(self, ticket_id: int, sender: str, text: str) -> Message:
        return self._callcenter.add_message(ticket_id=ticket_id, sender=sender, text=text)

    def listar_historico_cliente(self, contact_id: int) -> List[ConversationRecord]:
        records = self._callcenter._list_conversations_by_contact(contact_id)
        return sorted(
            records,
            key=lambda record: (record.last_activity_at, record.ticket.id),
            reverse=True,
        )

    def recuperar_conversa_anterior(self, contact_id: int) -> Optional[ConversationRecord]:
        history = self.listar_historico_cliente(contact_id)
        if len(history) < 2:
            return None
        return history[1]
