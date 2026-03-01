"""TMI API client wrapper."""

import logging
import re
import sys
from pathlib import Path
from typing import Callable, List, Optional, TypeVar, Union

import nh3  # type: ignore[import-untyped]

# Add tmi-client to path
tmi_client_path = Path.home() / "Projects" / "tmi-clients" / "python-client-generated"
if tmi_client_path.exists():
    sys.path.insert(0, str(tmi_client_path))
else:
    raise ImportError(
        f"TMI Python client not found at {tmi_client_path}. "
        "Please ensure it's available at ~/Projects/tmi-clients/python-client-generated"
    )

import tmi_client  # noqa: E402  # type: ignore[import-not-found]
from tmi_client.api_client import ApiClient  # noqa: E402  # type: ignore[import-not-found]
from tmi_client.configuration import Configuration  # noqa: E402  # type: ignore[import-not-found]
from tmi_client.models import (  # noqa: E402  # type: ignore[import-not-found]
    CreateDiagramRequest,
    DiagramListItem,
    Metadata,
    Note,
    NoteInput,
    Repository,
    ThreatInput,
    ThreatModel,
)

from tmi_client.rest import ApiException  # noqa: E402  # type: ignore[import-not-found]

from tmi_tf.auth import TMIAuthenticator  # noqa: E402
from tmi_tf.config import Config  # noqa: E402

logger = logging.getLogger(__name__)

T = TypeVar("T")


ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "br", "hr", "span", "div",
    "strong", "em", "del", "code", "pre",
    "a", "img",
    "ul", "ol", "li", "blockquote",
    "table", "colgroup", "col", "thead", "tbody", "tr", "th", "td",
    "input",
    "svg", "path", "g", "rect", "circle", "line", "polygon", "text", "tspan",
}  # fmt: skip

ALLOWED_ATTRIBUTES = {
    "*": {
        "href", "src", "alt", "title", "class", "id", "style",
        "type", "checked", "disabled",
        "data-line", "data-sourcepos",
        "target",
        "width", "height",
        "viewBox", "xmlns", "fill", "stroke", "stroke-width",
        "d", "x", "y", "x1", "y1", "x2", "y2", "points", "transform",
    },
}  # fmt: skip


def _escape_template_patterns(content: str) -> str:
    """Escape template injection patterns outside code blocks.

    The TMI server rejects content containing ``${``, ``{{``, or ``<%``
    outside of fenced code blocks and inline code spans.  We replace the
    leading character of each pattern with its HTML entity so the server
    validation passes while the browser still renders the intended glyph.

    Replacements (outside code only):
        ``${``  -> ``&#36;{``   (``$`` as HTML entity)
        ``{{``  -> ``&#123;{``  (first ``{`` as HTML entity)
        ``<%``  -> ``&lt;%``    (``<`` as HTML entity)
    """
    if not content:
        return content

    # Split content into code (fenced blocks and inline code) vs. prose.
    # Using a capturing group so that the delimiters are included in the
    # result list — odd-indexed elements are code, even are prose.
    segments = re.split(r"(```[^\n]*\n[\s\S]*?\n```|`[^`\n]+`)", content)

    result: list[str] = []
    for i, segment in enumerate(segments):
        if i % 2 == 1:
            # Inside a code block / inline code — keep as-is
            result.append(segment)
        else:
            # Prose — escape template-injection patterns
            segment = segment.replace("${", "&#36;{")
            segment = segment.replace("{{", "&#123;{")
            segment = segment.replace("<%", "&lt;%")
            result.append(segment)
    return "".join(result)


def sanitize_content_for_api(content: str) -> str:
    """
    Sanitize content to match TMI API requirements.

    Uses nh3 (Python equivalent of DOMPurify/bluemonday) to sanitize HTML,
    allowing only the tags and attributes accepted by the TMI platform.
    Also:
    - Escapes template injection patterns (``${``, ``{{``, ``<%``) outside
      code blocks so the server does not reject the content.
    - Removes control characters (U+0000-U+001F) except newline, carriage
      return, tab.
    - Removes characters above U+FFFF (emoji and supplementary Unicode).

    Args:
        content: Raw content string

    Returns:
        Sanitized content string that matches API requirements
    """
    if not content:
        return content

    # Sanitize HTML: allow only permitted tags and attributes
    # link_rel=None prevents nh3 from adding rel="noopener noreferrer" to links
    sanitized = nh3.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        link_rel=None,
    )

    # Escape template injection patterns outside code blocks
    sanitized = _escape_template_patterns(sanitized)

    # Replace characters outside the allowed range
    # Keep: U+0020-U+FFFF, \n (U+000A), \r (U+000D), \t (U+0009)
    def char_filter(char: str) -> str:
        code = ord(char)
        if code in (0x0A, 0x0D, 0x09):
            return char
        if 0x0020 <= code <= 0xFFFF:
            return char
        return " "

    sanitized = "".join(char_filter(c) for c in sanitized)
    return sanitized


class TMIClient:
    """Wrapper around TMI API client with authentication."""

    def __init__(self, config: Config, auth_token: Optional[str] = None):
        """
        Initialize TMI client.

        Args:
            config: Application configuration
            auth_token: Optional pre-authenticated JWT token
        """
        self.config = config

        # Configure TMI API client
        tmi_config = Configuration()
        tmi_config.host = config.tmi_server_url

        # Set authentication token
        if auth_token:
            tmi_config.api_key["bearerAuth"] = auth_token
            tmi_config.api_key_prefix["bearerAuth"] = "Bearer"

            # WORKAROUND: The generated client has an empty auth_settings() method
            # We need to monkey-patch it to properly set the Authorization header
            def auth_settings_override(self):
                return {
                    "bearerAuth": {
                        "type": "api_key",
                        "in": "header",
                        "key": "Authorization",
                        "value": self.get_api_key_with_prefix("bearerAuth"),
                    }
                }

            # Bind the override method to the configuration instance
            tmi_config.auth_settings = auth_settings_override.__get__(
                tmi_config, Configuration
            )

        self.api_client = ApiClient(configuration=tmi_config)
        self.threat_models_api = tmi_client.ThreatModelsApi(self.api_client)
        self.sub_resources_api = tmi_client.ThreatModelSubResourcesApi(self.api_client)

        logger.info(f"TMI client initialized for {config.tmi_server_url}")

    @classmethod
    def create_authenticated(
        cls, config: Config, force_refresh: bool = False
    ) -> "TMIClient":
        """
        Create authenticated TMI client.

        Args:
            config: Application configuration
            force_refresh: Force new authentication

        Returns:
            Authenticated TMI client
        """
        authenticator = TMIAuthenticator(config)
        token = authenticator.get_token(force_refresh=force_refresh)
        return cls(config, auth_token=token)

    def _reauthenticate(self) -> None:
        """Force re-authentication and reconfigure the API clients with the new token."""
        logger.info("Re-authenticating with TMI server...")
        authenticator = TMIAuthenticator(self.config)
        authenticator.token_cache.clear_token()
        token = authenticator.get_token(force_refresh=True)
        new_client = TMIClient(self.config, auth_token=token)
        self.api_client = new_client.api_client
        self.threat_models_api = new_client.threat_models_api
        self.sub_resources_api = new_client.sub_resources_api

    def _call_with_auth_retry(self, api_call: Callable[[], T]) -> T:
        """Execute an API call, retrying once with re-authentication on 401."""
        try:
            return api_call()
        except ApiException as e:
            if e.status == 401:
                logger.warning(
                    "Received 401 Unauthorized, re-authenticating and retrying..."
                )
                self._reauthenticate()
                return api_call()
            raise

    def get_threat_model(self, threat_model_id: str) -> ThreatModel:
        """
        Get threat model by ID.

        Args:
            threat_model_id: Threat model UUID

        Returns:
            ThreatModel object with all resources
        """
        logger.info(f"Fetching threat model: {threat_model_id}")
        try:
            threat_model = self._call_with_auth_retry(
                lambda: self.threat_models_api.get_threat_model(threat_model_id)
            )
            logger.info(f"Retrieved threat model: {threat_model.name}")
            return threat_model
        except Exception as e:
            logger.error(f"Failed to get threat model: {e}")
            raise

    def get_threat_model_repositories(self, threat_model_id: str) -> List[Repository]:
        """
        Get all repositories for a threat model.

        Args:
            threat_model_id: Threat model UUID

        Returns:
            List of Repository objects
        """
        logger.info(f"Fetching repositories for threat model: {threat_model_id}")
        try:
            response = self._call_with_auth_retry(
                lambda: self.sub_resources_api.get_threat_model_repositories(
                    threat_model_id
                )
            )
            repositories = response.repositories
            logger.info(f"Retrieved {len(repositories)} repositories")
            return repositories
        except Exception as e:
            logger.error(f"Failed to get repositories: {e}")
            raise

    def create_note(
        self, threat_model_id: str, name: str, content: str, description: str = ""
    ) -> Note:
        """
        Create a note in a threat model.

        Args:
            threat_model_id: Threat model UUID
            name: Note name
            content: Note content (markdown)
            description: Note description

        Returns:
            Created Note object
        """
        logger.info(f"Creating note '{name}' in threat model {threat_model_id}")
        try:
            # Sanitize content to match API requirements
            sanitized_content = sanitize_content_for_api(content)
            sanitized_description = (
                sanitize_content_for_api(description) if description else description
            )

            note_input = NoteInput(
                name=name, content=sanitized_content, description=sanitized_description
            )
            note = self._call_with_auth_retry(
                lambda: self.sub_resources_api.create_threat_model_note(
                    note_input, threat_model_id
                )
            )
            logger.info(f"Note created successfully with ID: {note.id}")
            return note
        except Exception as e:
            logger.error(f"Failed to create note: {e}")
            raise

    def get_threat_model_notes(self, threat_model_id: str) -> List[Note]:
        """
        Get all notes for a threat model.

        Note: This returns NoteListItem objects which do NOT include the content field.
        Use get_note() to fetch individual notes with their full content.

        Args:
            threat_model_id: Threat model UUID

        Returns:
            List of NoteListItem objects (content not included)
        """
        logger.info(f"Fetching notes for threat model: {threat_model_id}")
        try:
            response = self._call_with_auth_retry(
                lambda: self.sub_resources_api.get_threat_model_notes(threat_model_id)
            )
            notes = response.notes
            logger.info(f"Retrieved {len(notes)} notes")
            return notes
        except Exception as e:
            logger.error(f"Failed to get notes: {e}")
            raise

    def get_note(self, threat_model_id: str, note_id: str) -> Note:
        """
        Get a specific note by ID with full content.

        Args:
            threat_model_id: Threat model UUID
            note_id: Note UUID

        Returns:
            Note object with content
        """
        logger.info(f"Fetching note {note_id} from threat model {threat_model_id}")
        try:
            note = self._call_with_auth_retry(
                lambda: self.sub_resources_api.get_threat_model_note(
                    threat_model_id, note_id
                )
            )
            logger.info(f"Retrieved note: {note.name}")
            return note
        except Exception as e:
            logger.error(f"Failed to get note: {e}")
            raise

    def update_note(
        self,
        threat_model_id: str,
        note_id: str,
        name: str,
        content: str,
        description: str = "",
    ) -> Note:
        """
        Update an existing note.

        Args:
            threat_model_id: Threat model UUID
            note_id: Note UUID
            name: Note name
            content: Note content (markdown)
            description: Note description

        Returns:
            Updated Note object
        """
        logger.info(f"Updating note {note_id} in threat model {threat_model_id}")
        try:
            # Sanitize content to match API requirements
            sanitized_content = sanitize_content_for_api(content)
            sanitized_description = (
                sanitize_content_for_api(description) if description else description
            )

            note_input = NoteInput(
                name=name, content=sanitized_content, description=sanitized_description
            )
            note = self._call_with_auth_retry(
                lambda: self.sub_resources_api.update_threat_model_note(
                    note_input, threat_model_id, note_id
                )
            )
            logger.info("Note updated successfully")
            return note
        except Exception as e:
            logger.error(f"Failed to update note: {e}")
            raise

    def find_note_by_name(self, threat_model_id: str, note_name: str) -> Optional[Note]:
        """
        Find a note by name in a threat model.

        Args:
            threat_model_id: Threat model UUID
            note_name: Note name to search for

        Returns:
            Note object if found, None otherwise
        """
        notes = self.get_threat_model_notes(threat_model_id)
        for note in notes:
            if note.name == note_name:
                return note
        return None

    def create_or_update_note(
        self, threat_model_id: str, name: str, content: str, description: str = ""
    ) -> Note:
        """
        Create a new note or update existing one with the same name.

        Args:
            threat_model_id: Threat model UUID
            name: Note name
            content: Note content (markdown)
            description: Note description

        Returns:
            Created or updated Note object
        """
        existing_note = self.find_note_by_name(threat_model_id, name)

        if existing_note:
            logger.info(f"Note '{name}' already exists, updating...")
            return self.update_note(
                threat_model_id, existing_note.id, name, content, description
            )
        else:
            logger.info(f"Creating new note '{name}'...")
            return self.create_note(threat_model_id, name, content, description)

    def create_diagram(self, threat_model_id: str, name: str) -> str:
        """
        Create a new diagram in a threat model.

        Args:
            threat_model_id: Threat model UUID
            name: Diagram name

        Returns:
            Created diagram ID
        """
        logger.info(f"Creating diagram '{name}' in threat model {threat_model_id}")
        try:
            request = CreateDiagramRequest(name=name, type="DFD-1.0.0")
            diagram = self._call_with_auth_retry(
                lambda: self.sub_resources_api.create_threat_model_diagram(
                    request, threat_model_id
                )
            )
            diagram_id = diagram.id
            logger.info(f"Diagram created successfully with ID: {diagram_id}")
            return diagram_id
        except Exception as e:
            logger.error(f"Failed to create diagram: {e}")
            raise

    def update_diagram_cells(
        self, threat_model_id: str, diagram_id: str, cells: List[dict]
    ) -> dict:
        """
        Update diagram with cells using JSON Patch.

        Args:
            threat_model_id: Threat model UUID
            diagram_id: Diagram UUID
            cells: List of cell objects in X6 format

        Returns:
            Updated DfdDiagram dict
        """
        logger.info(
            f"Updating diagram {diagram_id} with {len(cells)} cells in threat model {threat_model_id}"
        )
        try:
            # Use JSON Patch to update the cells field
            # JSON Patch operation: replace the /cells path with new cells
            patch_operations = [{"op": "replace", "path": "/cells", "value": cells}]

            diagram = self._call_with_auth_retry(
                lambda: self.sub_resources_api.patch_threat_model_diagram(
                    patch_operations, threat_model_id, diagram_id
                )
            )
            logger.info("Diagram updated successfully")
            return diagram.to_dict()
        except Exception as e:
            logger.error(f"Failed to update diagram: {e}")
            raise

    def get_threat_model_diagrams(self, threat_model_id: str) -> List[DiagramListItem]:
        """
        Get all diagrams for a threat model.

        Args:
            threat_model_id: Threat model UUID

        Returns:
            List of DiagramListItem objects
        """
        logger.info(f"Fetching diagrams for threat model: {threat_model_id}")
        try:
            response = self._call_with_auth_retry(
                lambda: self.sub_resources_api.get_threat_model_diagrams(
                    threat_model_id
                )
            )
            diagrams = response.diagrams
            logger.info(f"Retrieved {len(diagrams)} diagrams")
            return diagrams
        except Exception as e:
            logger.error(f"Failed to get diagrams: {e}")
            raise

    def find_diagram_by_name(
        self, threat_model_id: str, name: str
    ) -> Optional[DiagramListItem]:
        """
        Find a diagram by name in a threat model.

        Args:
            threat_model_id: Threat model UUID
            name: Diagram name to search for

        Returns:
            Diagram dict if found, None otherwise
        """
        diagrams = self.get_threat_model_diagrams(threat_model_id)
        for diagram in diagrams:
            if diagram.name == name:
                return diagram
        return None

    def create_or_update_diagram(
        self, threat_model_id: str, name: str, cells: List[dict]
    ) -> dict:
        """
        Create a new diagram or update existing one with the same name.

        Args:
            threat_model_id: Threat model UUID
            name: Diagram name
            cells: List of cell objects in X6 format

        Returns:
            Created or updated Diagram dict
        """
        existing_diagram = self.find_diagram_by_name(threat_model_id, name)

        if existing_diagram:
            logger.info(f"Diagram '{name}' already exists, updating...")
            raw_id = existing_diagram.id
            diagram_id = str(raw_id) if raw_id else ""
            return self.update_diagram_cells(threat_model_id, diagram_id, cells)
        else:
            logger.info(f"Creating new diagram '{name}'...")
            diagram_id = self.create_diagram(threat_model_id, name)
            return self.update_diagram_cells(threat_model_id, diagram_id, cells)

    def create_threat(
        self,
        threat_model_id: str,
        name: str,
        threat_type: Union[str, List[str]],
        description: Optional[str] = None,
        mitigation: Optional[str] = None,
        severity: Optional[str] = None,
        score: Optional[float] = None,
        cvss: Optional[List[dict]] = None,
        cwe_id: Optional[List[str]] = None,
        status: Optional[str] = None,
        diagram_id: Optional[str] = None,
        cell_id: Optional[str] = None,
        metadata: Optional[List[dict]] = None,
    ) -> dict:
        """
        Create a new threat in a threat model.

        Args:
            threat_model_id: Threat model UUID
            name: Threat name (required)
            threat_type: Type or category of threat as list or string (required)
            description: Description of the threat and risk
            mitigation: Recommended or planned mitigation(s)
            severity: Severity level (e.g., Critical, High, Medium, Low)
            score: CVSS base score (0.0-10.0)
            cvss: List of CVSS vector/score dicts
            cwe_id: List of CWE identifiers (e.g., ["CWE-284"])
            status: Current status (e.g., Open, In Progress, Resolved)
            diagram_id: Associated diagram UUID
            cell_id: Associated cell UUID in the diagram
            metadata: List of metadata dicts with 'key' and 'value' keys

        Returns:
            Created Threat object as dict
        """
        logger.info(f"Creating threat '{name}' in threat model {threat_model_id}")
        try:
            # Ensure threat_type is a list
            if isinstance(threat_type, str):
                threat_type_list = [
                    t.strip() for t in threat_type.split(",") if t.strip()
                ]
            else:
                threat_type_list = threat_type

            # Convert metadata dicts to Metadata objects if provided
            metadata_objects = None
            if metadata:
                metadata_objects = [
                    Metadata(key=m["key"], value=m["value"]) for m in metadata
                ]

            threat_input = ThreatInput(
                name=sanitize_content_for_api(name) if name else name,
                threat_type=threat_type_list,
                description=sanitize_content_for_api(description)
                if description
                else description,
                mitigation=sanitize_content_for_api(mitigation)
                if mitigation
                else mitigation,
                severity=severity,
                score=score,
                cvss=cvss,
                cwe_id=cwe_id,
                status=status,
                diagram_id=diagram_id,
                cell_id=cell_id,
                metadata=metadata_objects,
            )
            threat = self._call_with_auth_retry(
                lambda: self.sub_resources_api.create_threat_model_threat(
                    threat_input, threat_model_id
                )
            )
            logger.info(f"Threat created successfully with ID: {threat.id}")
            return threat.to_dict()
        except Exception as e:
            logger.error(f"Failed to create threat: {e}")
            raise

    def set_note_metadata(
        self,
        threat_model_id: str,
        note_id: str,
        metadata: List[dict],
    ) -> List[dict]:
        """
        Set metadata on a note.

        Args:
            threat_model_id: Threat model UUID
            note_id: Note UUID
            metadata: List of metadata dicts with 'key' and 'value' keys

        Returns:
            List of created metadata dicts
        """
        logger.info(f"Setting metadata on note {note_id}")
        try:
            metadata_objects = [
                Metadata(key=m["key"], value=m["value"]) for m in metadata
            ]
            result = self._call_with_auth_retry(
                lambda: self.sub_resources_api.bulk_create_note_metadata(
                    metadata_objects, threat_model_id, note_id
                )
            )
            logger.info(f"Metadata set successfully: {len(metadata)} items")
            return [m.to_dict() for m in result]
        except Exception as e:
            logger.error(f"Failed to set note metadata: {e}")
            raise

    def set_diagram_metadata(
        self,
        threat_model_id: str,
        diagram_id: str,
        metadata: List[dict],
    ) -> List[dict]:
        """
        Set metadata on a diagram.

        Args:
            threat_model_id: Threat model UUID
            diagram_id: Diagram UUID
            metadata: List of metadata dicts with 'key' and 'value' keys

        Returns:
            List of created metadata dicts
        """
        logger.info(f"Setting metadata on diagram {diagram_id}")
        try:
            metadata_objects = [
                Metadata(key=m["key"], value=m["value"]) for m in metadata
            ]
            result = self._call_with_auth_retry(
                lambda: self.sub_resources_api.bulk_create_diagram_metadata(
                    metadata_objects, threat_model_id, diagram_id
                )
            )
            logger.info(f"Metadata set successfully: {len(metadata)} items")
            return [m.to_dict() for m in result]
        except Exception as e:
            logger.error(f"Failed to set diagram metadata: {e}")
            raise
