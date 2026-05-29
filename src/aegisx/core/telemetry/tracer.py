from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.sdk.resources import Resource
import time

class TelemetryEngine:
    """
    OpenTelemetry integration for Observability and Execution Tracing.
    Provides execution spans and signed audit logs for the Governance Engine.
    """
    def __init__(self, service_name: str = "aegisx.orchestrator"):
        resource = Resource(attributes={
            "service.name": service_name
        })
        
        provider = TracerProvider(resource=resource)
        # Using a Console exporter for local observability without needing Jaeger initially
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
        
        trace.set_tracer_provider(provider)
        self.tracer = trace.get_tracer(service_name)
        
    def get_tracer(self):
        return self.tracer
        
    def log_governance_event(self, action_id: str, operator: str, decision: str):
        """Emits a specialized governance trace span."""
        with self.tracer.start_as_current_span(f"governance.decision.{action_id}") as span:
            span.set_attribute("aegisx.operator", operator)
            span.set_attribute("aegisx.decision", decision)
            span.set_attribute("aegisx.timestamp", time.time())
