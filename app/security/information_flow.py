"""Basic information-flow tracking for GUARDIAN MCP."""

from typing import Any


# Demo classification labels, from least to most sensitive.
LABEL_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


class InformationFlowTracker:
    """Track data labels and check whether a destination is permitted."""

    def __init__(self) -> None:
        self._data_labels: dict[str, str] = {}

    def label_data(self, data_id: str, label: str) -> dict[str, Any]:
        """Assign a sensitivity label to a data item."""

        if not isinstance(data_id, str) or not data_id.strip():
            return {
                "decision": "BLOCK",
                "reason": "A valid data identifier is required.",
            }

        if label not in LABEL_LEVELS:
            return {
                "decision": "BLOCK",
                "reason": "Unknown sensitivity label.",
            }

        self._data_labels[data_id] = label

        return {
            "decision": "ALLOW",
            "data_id": data_id,
            "label": label,
            "reason": "Sensitivity label recorded.",
        }

    def check_flow(
        self,
        data_id: str,
        destination: str,
        maximum_label: str = "internal",
    ) -> dict[str, Any]:
        """Block a flow when its data label exceeds the destination limit."""

        label = self._data_labels.get(data_id)

        if label is None:
            return {
                "decision": "BLOCK",
                "reason": "Data has no recorded sensitivity label.",
            }

        if destination not in {"local", "approved_internal"}:
            return {
                "decision": "BLOCK",
                "reason": "Destination is not approved.",
                "label": label,
            }

        if maximum_label not in LABEL_LEVELS:
            return {
                "decision": "BLOCK",
                "reason": "Unknown destination sensitivity limit.",
            }

        if LABEL_LEVELS[label] > LABEL_LEVELS[maximum_label]:
            return {
                "decision": "BLOCK",
                "reason": "Data sensitivity exceeds the destination limit.",
                "label": label,
                "maximum_label": maximum_label,
            }

        return {
            "decision": "ALLOW",
            "reason": "Data flow is permitted by the configured label limit.",
            "label": label,
            "maximum_label": maximum_label,
        }
