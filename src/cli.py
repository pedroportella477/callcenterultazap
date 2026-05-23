from __future__ import annotations

from pprint import pprint

from src.callcenter import CallCenter


def main() -> None:
    center = CallCenter()

    maria = center.create_contact("Maria Souza", "+55 (11) 99999-1001")
    joao = center.create_contact("Joao Lima", "+55 11 98888-2002")

    t1 = center.open_ticket(maria.id, queue="comercial")
    t2 = center.open_ticket(joao.id, queue="suporte")

    center.assign_ticket(t1.id, "ana")
    center.assign_ticket(t2.id, "bruno")

    center.add_message(t1.id, sender="customer", text="Oi, quero saber dos planos.")
    center.add_message(t1.id, sender="agent", text="Perfeito, vou te apresentar as opcoes.")
    center.change_status(t1.id, "resolved")
    center.add_message(t1.id, sender="customer", text="Tenho mais uma duvida.")

    print("Tickets (all):")
    for ticket in center.list_tickets():
        print(ticket)

    print("\nTickets (pending):")
    for ticket in center.list_tickets(status="pending"):
        print(ticket)

    print("\nMetrics:")
    pprint(center.get_metrics())


if __name__ == "__main__":
    main()
