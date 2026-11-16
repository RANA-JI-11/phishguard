from fastapi import APIRouter, Depends

from app import models, schemas, auth
from app.ai_agent import agent_chat

router = APIRouter(prefix="/agent", tags=["ai-agent"])


@router.post("/chat", response_model=schemas.AgentChatResponse)
def chat(
    payload: schemas.AgentChatRequest,
    user: models.User = Depends(auth.get_current_user),
):
    """
    Stateless conversational endpoint. The frontend keeps the message history
    (e.g. in React state) and is expected to send it back on the NEXT call if
    it wants multi-turn context - for a v1 we just handle single-turn here.
    Extend `history` param if you want full multi-turn threads.
    """
    language = payload.language or user.preferred_language
    reply = agent_chat(payload.message, payload.url, history=[], language=language)
    return {"reply": reply}
