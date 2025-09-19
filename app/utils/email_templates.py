from datetime import datetime
from typing import Dict

APP_NAME = "Kidora"

def welcome_email(first_name: str | None) -> Dict[str, str]:
    name = first_name or "there"
    subject = f"Welcome to {APP_NAME}!"
    body = (
        f"Hi {name},\n\n"
        f"Thanks for creating your {APP_NAME} account. We're excited to have you on board.\n"
        "You can start browsing products and placing orders right away.\n\n"
        "Happy shopping!\n"
        f"-- The {APP_NAME} Team"
    )
    return {"subject": subject, "body": body}


def order_confirmation(order_id: int, total: float, item_count: int) -> Dict[str, str]:
    subject = f"Order #{order_id} Confirmation"
    body = (
        f"Thank you for your order!\n\n"
        f"Order ID: {order_id}\n"
        f"Items: {item_count}\nTotal: {total:.2f} BDT\n\n"
        "We'll notify you when the status changes."
    )
    return {"subject": subject, "body": body}


def order_status_update(order_id: int, new_status: str) -> Dict[str, str]:
    subject = f"Order #{order_id} Status Updated"
    body = (
        f"Your order #{order_id} status is now: {new_status}.\n"
        "Thank you for shopping with us."
    )
    return {"subject": subject, "body": body}


def payment_status_update(order_id: int, new_status: str) -> Dict[str, str]:
    subject = f"Order #{order_id} Payment {new_status.capitalize()}"
    body = (
        f"Payment status for order #{order_id} is now: {new_status}.\n"
        "If you have any questions, reply to this email."
    )
    return {"subject": subject, "body": body}


def password_reset_code(code: str) -> Dict[str, str]:
    subject = "Your Password Reset Code"
    body = (
        "We received a request to reset your password.\n\n"
        f"Use this code: {code}\n"
        "This code will expire in 10 minutes. If you did not request a reset, you can ignore this email.\n\n"
        f"-- The {APP_NAME} Team"
    )
    return {"subject": subject, "body": body}


def password_reset_success() -> Dict[str, str]:
    subject = "Your Password Has Been Reset"
    body = (
        "This is a confirmation that your password was successfully reset.\n"
        "If you did not perform this action, contact support immediately."
    )
    return {"subject": subject, "body": body}
