#!/usr/bin/env python3
"""UDP relay that emulates a long browser path in front of a local nox-kps.

Each direction gets a one-way delay and optional random loss. The
server-to-client direction can also get a bottleneck link: a rate limit with
a drop-tail queue, like a home router or an access link.

Usage: relay.py --listen PORT --target PORT [--delay MS] [--loss P]
                [--rate-mbit R --queue-kb Q] [--seed N]
"""
import argparse
import asyncio
import random
import time


class Link:
    """Delay, loss and an optional rate limit with a drop-tail queue."""

    def __init__(self, loop, delay_s, loss, rate_bps, queue_bytes, rng, name):
        self.loop, self.delay, self.loss = loop, delay_s, loss
        self.rate, self.queue, self.rng, self.name = rate_bps, queue_bytes, rng, name
        self.busy_until = 0.0
        self.sent = self.lost = self.dropped = 0

    def send(self, deliver, data):
        self.sent += 1
        if self.loss and self.rng.random() < self.loss:
            self.lost += 1
            return
        if self.rate:
            now = time.monotonic()
            backlog = max(0.0, self.busy_until - now) * self.rate
            if backlog + len(data) > self.queue:
                self.dropped += 1
                return
            self.busy_until = max(self.busy_until, now) + len(data) / self.rate
            at = self.busy_until - now + self.delay
        else:
            at = self.delay
        self.loop.call_later(at, deliver, data)


class Back(asyncio.DatagramProtocol):
    def __init__(self, front, client):
        self.front, self.client = front, client

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, _addr):
        self.front.down.send(lambda d: self.front.transport.sendto(d, self.client), data)


class Front(asyncio.DatagramProtocol):
    def __init__(self, loop, target, up, down):
        self.loop, self.target, self.up, self.down = loop, target, up, down
        self.backs = {}

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.up.send(lambda d: asyncio.ensure_future(self.forward(d, addr)), data)

    async def forward(self, data, addr):
        back = self.backs.get(addr)
        if back is None:
            _, back = await self.loop.create_datagram_endpoint(
                lambda: Back(self, addr), local_addr=("127.0.0.1", 0)
            )
            self.backs[addr] = back
        back.transport.sendto(data, self.target)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, required=True)
    p.add_argument("--target", type=int, required=True)
    p.add_argument("--delay", type=float, default=137.0, help="one-way delay, ms")
    p.add_argument("--loss", type=float, default=0.0, help="random loss per packet and direction")
    p.add_argument("--rate-mbit", type=float, default=0.0, help="server-to-client rate, 0 = unlimited")
    p.add_argument("--queue-kb", type=float, default=64.0, help="bottleneck queue, KiB")
    p.add_argument("--seed", type=int, default=None)
    a = p.parse_args()
    rng = random.Random(a.seed)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    up = Link(loop, a.delay / 1000, a.loss, 0, 0, rng, "up")
    down = Link(loop, a.delay / 1000, a.loss, a.rate_mbit * 125_000, a.queue_kb * 1024, rng, "down")
    loop.run_until_complete(
        loop.create_datagram_endpoint(
            lambda: Front(loop, ("127.0.0.1", a.target), up, down), local_addr=("0.0.0.0", a.listen)
        )
    )
    print(f"relay {a.listen} -> {a.target} delay {a.delay} ms loss {a.loss} "
          f"rate {a.rate_mbit} Mbit/s queue {a.queue_kb} KiB", flush=True)

    def report():
        for link in (up, down):
            print(f"{link.name}: sent {link.sent} lost {link.lost} queue-dropped {link.dropped}", flush=True)
        loop.call_later(5, report)

    loop.call_later(5, report)
    loop.run_forever()


if __name__ == "__main__":
    main()
