import unittest

from src.callcenter import AtendimentoService, CallCenter, normalize_phone


class CallCenterTests(unittest.TestCase):
    def test_phone_normalization(self):
        self.assertEqual(normalize_phone("+55 (11) 99999-0001"), "5511999990001")

    def test_contact_dedup_by_phone(self):
        center = CallCenter()
        c1 = center.create_contact("Maria", "(11) 99999-0001")
        c2 = center.create_contact("Maria Souza", "11 99999 0001")
        self.assertEqual(c1.id, c2.id)
        self.assertEqual(center.get_metrics()["contacts"], 1)

    def test_open_assign_and_change_status(self):
        center = CallCenter()
        contact = center.create_contact("Carlos", "11999990002")
        ticket = center.open_ticket(contact.id, queue="suporte")

        self.assertEqual(ticket.status, "open")
        self.assertIsNone(ticket.agent)

        center.assign_ticket(ticket.id, "ana")
        center.change_status(ticket.id, "pending")
        updated = center.list_tickets()[0]
        self.assertEqual(updated.agent, "ana")
        self.assertEqual(updated.status, "pending")

    def test_message_registration(self):
        center = CallCenter()
        contact = center.create_contact("Julia", "11999990003")
        ticket = center.open_ticket(contact.id, queue="financeiro")

        m1 = center.add_message(ticket.id, sender="customer", text="Preciso da segunda via.")
        m2 = center.add_message(ticket.id, sender="agent", text="Claro, vou gerar agora.")

        messages = center.list_messages(ticket.id)
        self.assertEqual([m.id for m in messages], [m1.id, m2.id])
        self.assertEqual(messages[0].sender, "customer")
        self.assertEqual(messages[1].sender, "agent")

    def test_auto_reopen_to_pending_when_customer_replies(self):
        center = CallCenter()
        contact = center.create_contact("Fernanda", "11999990004")
        ticket = center.open_ticket(contact.id, queue="comercial")

        center.change_status(ticket.id, "resolved")
        center.add_message(ticket.id, sender="customer", text="Ainda estou com uma duvida.")

        updated = center.list_tickets()[0]
        self.assertEqual(updated.status, "pending")

    def test_ticket_filters_by_status_and_queue(self):
        center = CallCenter()
        c1 = center.create_contact("A", "11999990101")
        c2 = center.create_contact("B", "11999990102")
        c3 = center.create_contact("C", "11999990103")

        t1 = center.open_ticket(c1.id, queue="suporte")
        t2 = center.open_ticket(c2.id, queue="suporte")
        center.open_ticket(c3.id, queue="comercial")
        center.change_status(t2.id, "pending")
        center.change_status(t1.id, "resolved")

        pending = center.list_tickets(status="pending")
        suporte = center.list_tickets(queue="suporte")

        self.assertEqual([t.id for t in pending], [t2.id])
        self.assertEqual([t.id for t in suporte], [t1.id, t2.id])

    def test_metrics_summary(self):
        center = CallCenter()
        c1 = center.create_contact("A", "11999990201")
        c2 = center.create_contact("B", "11999990202")
        t1 = center.open_ticket(c1.id, queue="suporte")
        t2 = center.open_ticket(c2.id, queue="comercial")
        center.change_status(t2.id, "pending")
        center.add_message(t1.id, sender="customer", text="Oi")
        center.add_message(t1.id, sender="agent", text="Ola")
        center.add_message(t2.id, sender="customer", text="Bom dia")

        metrics = center.get_metrics()
        self.assertEqual(metrics["contacts"], 2)
        self.assertEqual(metrics["tickets"], 2)
        self.assertEqual(metrics["messages"], 3)
        self.assertEqual(metrics["status_summary"], {"open": 1, "pending": 1, "resolved": 0})

    def test_atendimento_service_registrar_conversa(self):
        center = CallCenter()
        service = AtendimentoService(center)
        contact = center.create_contact("Renata", "11999990301")
        ticket = center.open_ticket(contact.id, queue="suporte")

        message = service.registrar_conversa(ticket.id, sender="customer", text="Preciso de ajuda")
        self.assertEqual(message.ticket_id, ticket.id)
        self.assertEqual(message.sender, "customer")
        self.assertEqual(len(center.list_messages(ticket.id)), 1)

    def test_atendimento_service_listar_historico_mais_recente_primeiro(self):
        center = CallCenter()
        service = AtendimentoService(center)
        contact = center.create_contact("Paula", "11999990302")
        ticket_1 = center.open_ticket(contact.id, queue="comercial")
        service.registrar_conversa(ticket_1.id, sender="customer", text="Primeiro contato")
        ticket_2 = center.open_ticket(contact.id, queue="suporte")
        service.registrar_conversa(ticket_2.id, sender="customer", text="Segundo contato")

        history = service.listar_historico_cliente(contact.id)
        self.assertEqual([item.ticket.id for item in history], [ticket_2.id, ticket_1.id])

    def test_atendimento_service_recuperar_conversa_anterior(self):
        center = CallCenter()
        service = AtendimentoService(center)
        contact = center.create_contact("Diego", "11999990303")
        ticket_1 = center.open_ticket(contact.id, queue="comercial")
        service.registrar_conversa(ticket_1.id, sender="customer", text="Conversa antiga")
        ticket_2 = center.open_ticket(contact.id, queue="suporte")
        service.registrar_conversa(ticket_2.id, sender="customer", text="Conversa atual")

        previous = service.recuperar_conversa_anterior(contact.id)
        self.assertIsNotNone(previous)
        self.assertEqual(previous.ticket.id, ticket_1.id)

    def test_atendimento_service_recuperar_conversa_anterior_none_when_single(self):
        center = CallCenter()
        service = AtendimentoService(center)
        contact = center.create_contact("Bianca", "11999990304")
        ticket = center.open_ticket(contact.id, queue="comercial")
        service.registrar_conversa(ticket.id, sender="customer", text="Conversa unica")

        previous = service.recuperar_conversa_anterior(contact.id)
        self.assertIsNone(previous)


if __name__ == "__main__":
    unittest.main()
