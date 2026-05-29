import json
import redis.asyncio as redis
from aegisx.core.schemas.events import EventMessage

class RedisEventBus:
    """
    Enterprise event streaming pipeline for AEGIS-X.
    Uses Redis Pub/Sub to broadcast real-time telemetry across distributed nodes.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._redis = None
        
    async def connect(self):
        if not self._redis:
            self._redis = redis.from_url(self.redis_url)
            
    async def publish_event(self, channel: str, event: EventMessage):
        """Broadcasts a structured event to the pub/sub channel."""
        await self.connect()
        # Convert Pydantic model to dict, then to JSON
        # Ensure datetimes are serialized properly
        event_json = event.model_dump_json()
        await self._redis.publish(channel, event_json)
        
    async def subscribe(self, channel: str):
        """Yields messages from the subscription."""
        await self.connect()
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        
        async for message in pubsub.listen():
            if message['type'] == 'message':
                yield message['data'].decode('utf-8')
                
    async def close(self):
        if self._redis:
            await self._redis.close()
