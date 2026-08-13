from dataclasses import dataclass, field
from datetime import datetime

from app.models.resource import ResourceType

_TYPE_HEADINGS = {
    ResourceType.host: "Hosts",
    ResourceType.vm: "VMs",
    ResourceType.storage: "Storage",
    ResourceType.network_device: "Network Devices",
}


@dataclass
class RenderNote:
    text: str
    author_email: str
    created_at: datetime


@dataclass
class RenderResource:
    resource_type: ResourceType
    fields: dict
    notes: list[RenderNote] = field(default_factory=list)


def render_client_doc(client_name: str, resources: list[RenderResource]) -> str:
    """Turns already-decrypted resources + notes into clean markdown, grouped by
    resource_type, produced entirely inside the request and never stored. This is
    what an agent (via the MCP server) actually reads."""
    lines = [f"# {client_name}", ""]

    by_type: dict[ResourceType, list[RenderResource]] = {}
    for r in resources:
        by_type.setdefault(r.resource_type, []).append(r)

    if not resources:
        lines.append("_No resources in scope for this token._")
        return "\n".join(lines)

    for resource_type, heading in _TYPE_HEADINGS.items():
        group = by_type.get(resource_type)
        if not group:
            continue
        lines.append(f"## {heading}")
        lines.append("")
        for r in group:
            name = r.fields.get("name") or "(unnamed)"
            lines.append(f"### {name}")
            for key, value in r.fields.items():
                if key == "name" or value in (None, ""):
                    continue
                lines.append(f"- **{key}**: {value}")
            if r.notes:
                lines.append("")
                lines.append("**Notes / History**")
                for note in r.notes:
                    ts = note.created_at.strftime("%Y-%m-%d %H:%M UTC")
                    lines.append(f"- _{ts}, {note.author_email}_: {note.text}")
            lines.append("")

    return "\n".join(lines)
