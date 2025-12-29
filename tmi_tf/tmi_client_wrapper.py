"""TMI API client wrapper."""

import logging
import sys
from pathlib import Path
from typing import List, Optional, Union

# Add tmi-client to path
tmi_client_path = Path.home() / "Projects" / "tmi-clients" / "python-client-generated"
if tmi_client_path.exists():
    sys.path.insert(0, str(tmi_client_path))
else:
    raise ImportError(
        f"TMI Python client not found at {tmi_client_path}. "
        "Please ensure it's available at ~/Projects/tmi-clients/python-client-generated"
    )

import tmi_client  # noqa: E402
from tmi_client.api_client import ApiClient  # noqa: E402
from tmi_client.configuration import Configuration  # noqa: E402
from tmi_client.models import (  # noqa: E402
    CreateDiagramRequest,
    DiagramListItem,
    Note,
    NoteInput,
    Repository,
    ThreatInput,
    ThreatModel,
)

from tmi_tf.auth import TMIAuthenticator  # noqa: E402
from tmi_tf.config import Config  # noqa: E402

logger = logging.getLogger(__name__)


def sanitize_content_for_api(content: str) -> str:
    """
    Sanitize content to match TMI API pattern: ^[\u0020-\uffff\n\r\t]*$

    This removes:
    - Control characters (U+0000-U+001F) except \n, \r, \t
    - Characters above U+FFFF (emoji and supplementary Unicode)

    Args:
        content: Raw content string

    Returns:
        Sanitized content string that matches API requirements
    """
    if not content:
        return content

    # Replace characters outside the allowed range
    # Keep: U+0020-U+FFFF, \n (U+000A), \r (U+000D), \t (U+0009)
    def char_filter(char: str) -> str:
        code = ord(char)
        # Allow newline, carriage return, tab
        if code in (0x0A, 0x0D, 0x09):
            return char
        # Allow space through U+FFFF
        if 0x0020 <= code <= 0xFFFF:
            return char
        # Replace everything else with space
        return " "

    sanitized = "".join(char_filter(c) for c in content)
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
            threat_model = self.threat_models_api.get_threat_model(threat_model_id)
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
            repositories = self.sub_resources_api.get_threat_model_repositories(
                threat_model_id
            )
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
            note = self.sub_resources_api.create_threat_model_note(
                note_input, threat_model_id
            )
            logger.info(f"Note created successfully with ID: {note.id}")
            return note
        except Exception as e:
            logger.error(f"Failed to create note: {e}")
            raise

    def get_threat_model_notes(self, threat_model_id: str) -> List[Note]:
        """
        Get all notes for a threat model.

        Args:
            threat_model_id: Threat model UUID

        Returns:
            List of Note objects
        """
        logger.info(f"Fetching notes for threat model: {threat_model_id}")
        try:
            notes = self.sub_resources_api.get_threat_model_notes(threat_model_id)
            logger.info(f"Retrieved {len(notes)} notes")
            return notes
        except Exception as e:
            logger.error(f"Failed to get notes: {e}")
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
            note = self.sub_resources_api.update_threat_model_note(
                note_input, threat_model_id, note_id
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
            diagram = self.sub_resources_api.create_threat_model_diagram(
                request, threat_model_id
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

            diagram = self.sub_resources_api.patch_threat_model_diagram(
                patch_operations, threat_model_id, diagram_id
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
            diagrams = self.sub_resources_api.get_threat_model_diagrams(threat_model_id)
            logger.info(f"Retrieved {len(diagrams)} diagrams")
            return diagrams
        except Exception as e:
            logger.error(f"Failed to get diagrams: {e}")
            raise

    def find_diagram_by_name(self, threat_model_id: str, name: str) -> Optional[dict]:
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
            diagram_id = existing_diagram.id
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
        description: str = None,
        mitigation: str = None,
        severity: str = None,
        status: str = None,
        diagram_id: str = None,
        cell_id: str = None,
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
            status: Current status (e.g., Open, In Progress, Resolved)
            diagram_id: Associated diagram UUID
            cell_id: Associated cell UUID in the diagram

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

            threat_input = ThreatInput(
                name=name,
                threat_type=threat_type_list,
                description=description,
                mitigation=mitigation,
                severity=severity,
                status=status,
                diagram_id=diagram_id,
                cell_id=cell_id,
            )
            threat = self.sub_resources_api.create_threat_model_threat(
                threat_input, threat_model_id
            )
            logger.info(f"Threat created successfully with ID: {threat.id}")
            return threat.to_dict()
        except Exception as e:
            logger.error(f"Failed to create threat: {e}")
            raise
