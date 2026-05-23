import unittest
from datetime import datetime, timedelta, timezone

from src.erp import (
    ERPIntegrationService,
    HubsoftClient,
    IXCSoftClient,
    MKSolutionsClient,
    SGPClient,
    VoalleClient,
)
from src.ultazap import UltaZapPlatform


class UltaZapPlatformTests(unittest.TestCase):
    def test_permissions_groups_filters_and_notes(self):
        app = UltaZapPlatform()
        app.grant_permission("ana", "campaign.send")
        self.assertTrue(app.has_permission("ana", "campaign.send"))

        contact = app.upsert_contact("Maria", "1199990001")
        ticket = app.open_ticket(contact.id, queue="suporte", agent="ana")
        app.move_ticket_to_group(ticket.id, "suporte-n1")
        app.add_agent_to_group("ana", "suporte-n1")
        self.assertTrue(app.can_agent_view_ticket("ana", ticket.id))
        self.assertFalse(app.can_agent_view_ticket("bruno", ticket.id))

        app.add_label(ticket.id, "vip")
        app.add_private_note(ticket.id, "Cliente prefere contato no periodo da tarde.")
        filtered = app.filter_tickets(queue="suporte", label="vip", agent="ana")
        self.assertEqual([t.id for t in filtered], [ticket.id])
        self.assertEqual(len(app.list_private_notes(ticket.id)), 1)

    def test_bot_quick_reply_media_team_chat_and_schedule(self):
        app = UltaZapPlatform()
        contact = app.upsert_contact("Joao", "1199990002")
        ticket = app.open_ticket(contact.id, queue="vendas", agent="ana")

        app.bot_primeiro_contato(ticket.id)
        app.add_quick_reply("/saudacao", "Ola! Em que posso ajudar?")
        app.send_quick_reply(ticket.id, "/saudacao")
        app.send_media(ticket.id, "image", "https://example.com/fatura.png")
        team_msg = app.post_team_message("ana", "Assumi o atendimento do Joao.")
        self.assertEqual(team_msg.sender, "ana")
        self.assertEqual(len(app.list_team_messages()), 1)
        self.assertEqual(len(app.list_media(ticket.id)), 1)

        app.schedule_message(
            ticket.id,
            "Retorno automatico agendado",
            when=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        sent = app.process_scheduled_messages()
        self.assertEqual(sent, 1)

        ai_hint = app.chatgpt_sugerir_resposta(ticket.id)
        self.assertIn("Sugestao IA:", ai_hint)

    def test_campaign_and_reports(self):
        app = UltaZapPlatform()
        c1 = app.upsert_contact("A", "1199990003")
        c2 = app.upsert_contact("B", "1199990004")
        total = app.run_campaign("campanha-junho", [c1.id, c2.id], "Promo especial")
        self.assertEqual(total, 2)
        report = app.relatorio()
        self.assertEqual(report["contacts"], 2)
        self.assertEqual(report["tickets"], 2)
        self.assertEqual(report["messages"], 2)


class ERPIntegrationTests(unittest.TestCase):
    def _build_service(self) -> ERPIntegrationService:
        return ERPIntegrationService(
            {
                "ixcsoft": IXCSoftClient(),
                "hubsoft": HubsoftClient(),
                "mksolutions": MKSolutionsClient(),
                "voalle": VoalleClient(),
                "sgp": SGPClient(),
            }
        )

    def test_healthcheck_all_providers(self):
        service = self._build_service()
        health = service.healthcheck()
        self.assertEqual(set(health.keys()), {"ixcsoft", "hubsoft", "mksolutions", "voalle", "sgp"})
        self.assertTrue(all(health.values()))

    def test_end_to_end_provider_contract(self):
        service = self._build_service()
        for provider in ("ixcsoft", "hubsoft", "mksolutions", "voalle", "sgp"):
            client = service.buscar_cliente(provider, "12345678901")
            self.assertIsNotNone(client)
            invoices = service.listar_faturas_em_aberto(provider, client.id)
            self.assertGreaterEqual(len(invoices), 1)
            ticket = service.abrir_chamado(provider, client.id, "Sem acesso ao portal")
            self.assertEqual(ticket.status, "open")
            self.assertIn(provider.upper().split()[0], ticket.protocol)


if __name__ == "__main__":
    unittest.main()
