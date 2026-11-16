import stripe
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas, auth
from app.config import settings, PLAN_LIMITS

router = APIRouter(prefix="/billing", tags=["billing"])
stripe.api_key = settings.STRIPE_SECRET_KEY

PRICE_MAP = {
    "pro": settings.STRIPE_PRICE_ID_PRO,
    "business": settings.STRIPE_PRICE_ID_BUSINESS,
}


@router.get("/plans")
def list_plans():
    """Public endpoint - the frontend pricing page reads straight from here
    so you only ever need to update prices in one place (app/config.py)."""
    return PLAN_LIMITS


@router.post("/checkout")
def create_checkout_session(
    payload: schemas.CheckoutRequest,
    user: models.User = Depends(auth.get_current_user),
):
    if payload.plan not in PRICE_MAP:
        raise HTTPException(status_code=400, detail="Unknown plan")
    if not settings.STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe is not configured on the server yet.")

    session = stripe.checkout.Session.create(
        mode="subscription",
        payment_method_types=["card"],
        line_items=[{"price": PRICE_MAP[payload.plan], "quantity": 1}],
        customer_email=user.email,
        client_reference_id=user.id,
        success_url="https://your-frontend-domain.com/billing/success",
        cancel_url="https://your-frontend-domain.com/billing/cancelled",
    )
    return {"checkout_url": session.url}


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Stripe calls this automatically when a payment succeeds/fails/cancels.
    Register this URL in your Stripe dashboard: https://yourdomain.com/billing/webhook
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_id = session.get("client_reference_id")
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if user:
            # Determine which plan was purchased from the line item price ID
            line_items = stripe.checkout.Session.list_line_items(session["id"])
            price_id = line_items["data"][0]["price"]["id"]
            plan = "pro" if price_id == settings.STRIPE_PRICE_ID_PRO else "business"
            user.plan = plan
            user.stripe_customer_id = session.get("customer")
            db.commit()

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        user = db.query(models.User).filter(
            models.User.stripe_customer_id == subscription.get("customer")
        ).first()
        if user:
            user.plan = "free"
            db.commit()

    return {"status": "ok"}
