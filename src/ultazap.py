from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from src.callcenter import AtendimentoService, CallCenter, Message, Ticket, normalize_phone


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class TeamMessage:
    id: int
    sender: str
    text: str
    created_at: datetime


@dataclass(frozen=True)
class ScheduledMessage:
    id: int
    ticket_id: int
    text: str
    when: datetime
    sent: bool


class UltaZapPlatform:
    def __init__(self, callcenter: Optional[CallCenter] = None) -> None:
        self.callcenter = callcenter or CallCenter()
        self.atendimento = AtendimentoService(self.callcenter)

        self._agent_permissions: Dict[str, Set[str]] = {}
        self._groups: Dict[str, Set[str]] = {}
        self._ticket_group: Dict[int, str] = {}
        self._quick_replies: Dict[str, str] = {}
        self._labels_by_ticket: Dict[int, Set[str]] = {}
        self._private_notes_by_ticket: Dict[int, List[str]] = {}
        self._custom_fields_by_contact: Dict[int, Dict[str, str]] = {}
        self._team_chat: List[TeamMessage] = []
        self._scheduled_messages: List[ScheduledMessage] = []
        self._media_by_ticket: Dict[int, List[dict]] = {}
        self._campaigns: Dict[str, List[str]] = {}

        self._team_message_seq = 1
        self._scheduled_seq = 1

    # Permissions and groups
    def grant_permission(self, agent: str, permission: str) -> None:
        self._agent_permissions.setdefault(agent.strip(), set()).add(permission.strip())

    def has_permission(self, agent: str, permission: str) -> bool:
        return permission.strip() in self._agent_permissions.get(agent.strip(), set())

    def add_group(self, group_name: str) -> None:
        group_name = group_name.strip()
        if not group_name:
            raise ValueError("group_name is required")
        self._groups.setdefault(group_name, set())

    def add_agent_to_group(self, agent: str, group_name: str) -> None:
        self.add_group(group_name)
        self._groups[group_name].add(agent.strip())

    def move_ticket_to_group(self, ticket_id: int, group_name: str) -> None:
        self.callcenter._require_ticket(ticket_id)
        self.add_group(group_name)
        self._ticket_group[ticket_id] = group_name

    def can_agent_view_ticket(self, agent: str, ticket_id: int) -> bool:
        self.callcenter._require_ticket(ticket_id)
        group = self._ticket_group.get(ticket_id)
        if group is None:
            return True
        return agent.strip() in self._groups.get(group, set())

    # CRM and custom fields
    def upsert_contact(self, name: str, phone: str):
        return self.callcenter.create_contact(name, normalize_phone(phone))

    def set_custom_field(self, contact_id: int, field_name: str, value: str) -> None:
        self.callcenter._require_contact(contact_id)
        field_name = field_name.strip()
        if not field_name:
            raise ValueError("field_name is required")
        self._custom_fields_by_contact.setdefault(contact_id, {})[field_name] = value.strip()

    def get_custom_fields(self, contact_id: int) -> Dict[str, str]:
        self.callcenter._require_contact(contact_id)
        return dict(self._custom_fields_by_contact.get(contact_id, {}))

    # Ticket helpers
    def open_ticket(self, contact_id: int, queue: str, agent: Optional[str] = None) -> Ticket:
        return self.callcenter.open_ticket(contact_id, queue, agent)

    def filter_tickets(
        self,
        status: Optional[str] = None,
        queue: Optional[str] = None,
        label: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> List[Ticket]:
        tickets = self.callcenter.list_tickets(status=status, queue=queue)
        if label:
            tickets = [t for t in tickets if label in self._labels_by_ticket.get(t.id, set())]
        if agent:
            tickets = [t for t in tickets if t.agent == agent]
        return tickets

    # Messages and bot/chatgpt style assistance
    def registrar_conversa(self, ticket_id: int, sender: str, text: str) -> Message:
        return self.atendimento.registrar_conversa(ticket_id, sender, text)

    def bot_primeiro_contato(self, ticket_id: int) -> Message:
        text = "Ola! Sou o bot da UltaZap. Informe CPF/CNPJ e descreva seu atendimento."
        return self.registrar_conversa(ticket_id, "agent", text)

    def chatgpt_sugerir_resposta(self, ticket_id: int) -> str:
        messages = self.callcenter.list_messages(ticket_id)
        if not messages:
            return "Posso ajudar com seu atendimento. Pode me dar mais detalhes?"
        last = messages[-1].text
        return f"Sugestao IA: Entendi. Sobre '{last}', vou verificar e retorno em instantes."

    # Quick replies, labels and private notes
    def add_quick_reply(self, shortcut: str, text: str) -> None:
        shortcut = shortcut.strip()
        text = text.strip()
        if not shortcut or not text:
            raise ValueError("shortcut and text are required")
        self._quick_replies[shortcut] = text

    def send_quick_reply(self, ticket_id: int, shortcut: str) -> Message:
        text = self._quick_replies.get(shortcut.strip())
        if text is None:
            raise ValueError("quick reply not found")
        return self.registrar_conversa(ticket_id, "agent", text)

    def add_label(self, ticket_id: int, label: str) -> None:
        self.callcenter._require_ticket(ticket_id)
        label = label.strip()
        if not label:
            raise ValueError("label is required")
        self._labels_by_ticket.setdefault(ticket_id, set()).add(label)

    def add_private_note(self, ticket_id: int, note: str) -> None:
        self.callcenter._require_ticket(ticket_id)
        note = note.strip()
        if not note:
            raise ValueError("note is required")
        self._private_notes_by_ticket.setdefault(ticket_id, []).append(note)

    def list_private_notes(self, ticket_id: int) -> List[str]:
        self.callcenter._require_ticket(ticket_id)
        return list(self._private_notes_by_ticket.get(ticket_id, []))

    # Team chat
    def post_team_message(self, sender: str, text: str) -> TeamMessage:
        sender = sender.strip()
        text = text.strip()
        if not sender or not text:
            raise ValueError("sender and text are required")
        message = TeamMessage(
            id=self._team_message_seq,
            sender=sender,
            text=text,
            created_at=_utc_now(),
        )
        self._team_message_seq += 1
        self._team_chat.append(message)
        return message

    def list_team_messages(self) -> List[TeamMessage]:
        return list(self._team_chat)

    # Scheduling and campaigns
    def schedule_message(self, ticket_id: int, text: str, when: datetime) -> ScheduledMessage:
        self.callcenter._require_ticket(ticket_id)
        if when.tzinfo is None:
            raise ValueError("when must be timezone aware")
        text = text.strip()
        if not text:
            raise ValueError("text is required")
        schedule = ScheduledMessage(
            id=self._scheduled_seq,
            ticket_id=ticket_id,
            text=text,
            when=when,
            sent=False,
        )
        self._scheduled_seq += 1
        self._scheduled_messages.append(schedule)
        return schedule

    def process_scheduled_messages(self, now: Optional[datetime] = None) -> int:
        now = now or _utc_now()
        sent_count = 0
        updated: List[ScheduledMessage] = []
        for item in self._scheduled_messages:
            if (not item.sent) and item.when <= now:
                self.registrar_conversa(item.ticket_id, "agent", item.text)
                updated.append(
                    ScheduledMessage(
                        id=item.id,
                        ticket_id=item.ticket_id,
                        text=item.text,
                        when=item.when,
                        sent=True,
                    )
                )
                sent_count += 1
            else:
                updated.append(item)
        self._scheduled_messages = updated
        return sent_count

    def run_campaign(self, campaign_name: str, contact_ids: List[int], text: str) -> int:
        campaign_name = campaign_name.strip()
        if not campaign_name:
            raise ValueError("campaign_name is required")
        text = text.strip()
        if not text:
            raise ValueError("text is required")

        sent_for: List[str] = []
        for contact_id in contact_ids:
            self.callcenter._require_contact(contact_id)
            ticket = self.callcenter.open_ticket(contact_id, queue="campanhas")
            self.registrar_conversa(ticket.id, "agent", text)
            sent_for.append(str(contact_id))
        self._campaigns[campaign_name] = sent_for
        return len(sent_for)

    # Media
    def send_media(self, ticket_id: int, media_type: str, url: str) -> None:
        self.callcenter._require_ticket(ticket_id)
        media_type = media_type.strip().lower()
        if media_type not in {"image", "video", "gif", "sticker", "file"}:
            raise ValueError("invalid media_type")
        url = url.strip()
        if not url:
            raise ValueError("url is required")
        self._media_by_ticket.setdefault(ticket_id, []).append(
            {"type": media_type, "url": url, "at": _utc_now().isoformat()}
        )

    def list_media(self, ticket_id: int) -> List[dict]:
        self.callcenter._require_ticket(ticket_id)
        return list(self._media_by_ticket.get(ticket_id, []))

    # Reports
    def relatorio(self) -> dict:
        base = self.callcenter.get_metrics()
        base["team_messages"] = len(self._team_chat)
        base["scheduled"] = len(self._scheduled_messages)
        base["labels"] = sum(len(labels) for labels in self._labels_by_ticket.values())
        return base
