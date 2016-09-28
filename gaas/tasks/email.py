from ..controllers import InvalidParameter, NotFound


def inject_dependencies(**kwargs):
    global session, user_manager, render
    session = kwargs["session"]
    user_manager = kwargs["user_manager"]
    render = kwargs["render"]
user_manager = None
session = None
render = None


def send_verification_email(username: str, port: int):
    """
    Do not call directly, this is executed by an rq worker.
    Use tasks.Scheduler.send_verification_email instead
    """
    try:
        user = user_manager.load_by_name(username)
    except (InvalidParameter, NotFound):
        # TODO log failure
        # If it's InvalidParameter there's no sense raising, since retries will always fail.
        # If it's NotFound, either the username is unknown or the user id is unknown.
        #   Either way, the next call, at best, will find a user that is NOT the user we had in mind when calling
        #   this function.  Don't retry this exception, either.
        return

    # User is already verified, no need to send another email
    if getattr(user, "verification_code", None) is None:
        return

    # TODO use config
    support = "gaas-support@moldyboot.com"
    support_bounce = "gaas-support+bounce@moldyboot.com"
    verification_url = "http://localhost:{}/verify/{}/{}".format(port, user.user_id, user.verification_code)
    message = {
        "src": support,
        "dst": user.email,
        "subject": "Please verify your email",
        "text": render("verify-email.txt", username=username, verification_url=verification_url),
        "html": render("verify-email.html", username=username, verification_url=verification_url),
        "reply_to": support,
        "return_path": support_bounce
    }
    send_email(session.client("ses"), **message)


def send_email(ses, src, dst, subject, text, html, reply_to, return_path):
    message = {
        "Source": src,
        "Destination": {"ToAddresses": [dst]},
        "Message": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {
                "Text": {"Data": text, "Charset": "UTF-8"},
                "Html": {"Data": html, "Charset": "UTF-8"}
            }
        },
        "ReplyToAddresses": [reply_to],
        "ReturnPath": return_path
    }
    ses.send_email(**message)
