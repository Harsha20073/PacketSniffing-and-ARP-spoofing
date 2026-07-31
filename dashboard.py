from rich.live import Live
from rich.table import Table
import time


def create_dashboard(stats, interface):

    table = Table(title="NetSentinel LIVE MONITOR")

    table.add_column("Metric")
    table.add_column("Value")

    table.add_row(
        "Interface",
        interface
    )

    table.add_row(
        "Packets",
        str(stats["Total"])
    )

    table.add_row(
        "TCP",
        str(stats["TCP"])
    )

    table.add_row(
        "UDP",
        str(stats["UDP"])
    )

    table.add_row(
        "ICMP",
        str(stats["ICMP"])
    )

    table.add_row(
        "ARP",
        str(stats["ARP"])
    )

    return table



def run_dashboard(stats, interface):

    with Live(
        create_dashboard(stats, interface),
        refresh_per_second=1
    ) as live:

        while True:

            live.update(
                create_dashboard(
                    stats,
                    interface
                )
            )

            time.sleep(1)
