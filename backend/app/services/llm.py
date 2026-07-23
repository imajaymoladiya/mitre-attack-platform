import logging
import httpx
from openai import OpenAI, APIConnectionError
from app.config import settings

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(self):
        self._openai_client = None
        self._groq_client = None
        self._local_model = None
        self.embedding_dimension = 384  # Default to all-MiniLM-L6-v2 dimension

    @property
    def openai_client(self):
        if self._openai_client is None:
            self._openai_client = OpenAI(
                base_url=settings.LLM_API_BASE,
                api_key="lm-studio"  # LM Studio does not require a real key
            )
        return self._openai_client

    @property
    def groq_client(self):
        if self._groq_client is None and settings.GROQ_API_KEY:
            logger.info("Initializing Groq API client...")
            self._groq_client = OpenAI(
                base_url="https://api.groq.com/openai/v1",
                api_key=settings.GROQ_API_KEY
            )
        return self._groq_client

    @property
    def local_model(self):
        """
        Lazily load sentence-transformers model to save memory and startup time
        unless local fallback is actively needed.
        """
        if self._local_model is None:
            logger.info("Initializing local SentenceTransformer model ('all-MiniLM-L6-v2')...")
            from sentence_transformers import SentenceTransformer
            self._local_model = SentenceTransformer('all-MiniLM-L6-v2')
            self.embedding_dimension = 384
        return self._local_model

    def get_embedding(self, text: str) -> list[float]:
        """
        Generates a vector embedding for a single text input.
        """
        return self.get_embeddings_batch([text])[0]

    def get_embeddings_batch(self, texts: list[str]) -> list[list[float]]:
        """
        Generates vector embeddings for a list of text inputs.
        Supports automatic fallback to local CPU model if LM Studio is offline.
        """
        if not texts:
            return []

        # Sanitize texts (replace newlines which can affect some embedding models)
        sanitized_texts = [t.replace("\n", " ") for t in texts]

        if not settings.USE_LOCAL_EMBEDDING_FALLBACK:
            try:
                logger.info(f"Generating {len(texts)} embeddings via LM Studio at {settings.LLM_API_BASE}")
                response = self.openai_client.embeddings.create(
                    input=sanitized_texts,
                    model=settings.LLM_MODEL_NAME
                )
                embeddings = [data.embedding for data in response.data]
                if embeddings:
                    self.embedding_dimension = len(embeddings[0])
                return embeddings
            except (APIConnectionError, httpx.ConnectError, Exception) as e:
                logger.warning(f"LM Studio connection failed: {e}. Falling back to local SentenceTransformer.")

        # Fallback to local CPU-based embedding generation
        try:
            embeddings = self.local_model.encode(sanitized_texts, show_progress_bar=False)
            self.embedding_dimension = 384
            return [vec.tolist() for vec in embeddings]
        except Exception as e:
            logger.error(f"Failed to generate local embeddings: {e}")
            # Return dummy zero-vectors as absolute last resort to prevent ingestion failure
            logger.warning("Returning zero vectors as absolute fallback.")
            return [[0.0] * self.embedding_dimension for _ in texts]

    def chat_complete(self, messages: list[dict], temperature: float = 0.7) -> str:
        """
        Generates a chat completion using Groq (if configured) or LM Studio,
        falling back to a rule-based AI helper if neither is accessible.
        """
        # Try Groq first if API key is provided
        if settings.GROQ_API_KEY:
            try:
                logger.info(f"Generating chat completion via Groq using model: {settings.GROQ_MODEL_NAME}")
                response = self.groq_client.chat.completions.create(
                    model=settings.GROQ_MODEL_NAME,
                    messages=messages,
                    temperature=temperature
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.warning(f"Groq chat completion failed: {e}. Trying LM Studio fallback.")

        # Try LM Studio
        try:
            logger.info(f"Generating chat completion via LM Studio using model: {settings.LLM_MODEL_NAME}")
            response = self.openai_client.chat.completions.create(
                model=settings.LLM_MODEL_NAME,
                messages=messages,
                temperature=temperature
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.warning(f"LM Studio chat completion failed: {e}. Running local fallback helper.")
            # Basic fallback response generator for testing when LLM runtime is offline
            user_msg = messages[-1]["content"] if messages else ""
            return (
                f"[Local Mock LLM Fallback (LLM runtime offline)]\n"
                f"You asked: '{user_msg}'\n"
                f"This is a placeholder response because the local LLM runtime was not accessible."
            )

# Global LLM instance
llm_service = LLMService()
