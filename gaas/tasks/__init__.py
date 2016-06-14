import rq
# Local task imports are inside the scheduler and inject_dependencies functions
# to avoid circular dependencies when using the Scheduler as a type annotation in
# controllers

__all__ = ["Scheduler"]


class Scheduler:
    def __init__(self, queue: rq.Queue):
        self.queue = queue

    def send_verification_email(self, username):
        from . import email
        self.queue.enqueue(email.send_verification_email, username)


def inject_dependencies(**kwargs):  # pragma: no cover
    from . import email
    """Central location for an rq worker to inject all the dependencies it needs"""
    email.inject_dependencies(**kwargs)
