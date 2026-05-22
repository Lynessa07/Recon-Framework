import random
import time


def random_delay():

    time.sleep(
        random.uniform(0.05, 0.3)
    )


def random_ttl():

    return random.randint(50, 120)


def spoofed_source_port():

    trusted_ports = [
        20,
        53,
        67,
        123,
        443
    ]

    return random.choice(
        trusted_ports
    )