from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, ValidationError
import yaml

# Define the structure of plugins configuration
class PluginConfig(BaseModel):
    enabled: bool = Field(default=False, description="Whether the plugin is enabled.")
    mode: Optional[str] = Field(None, description="Operational mode for the plugin (e.g., 'offline', 'online').")
    server_url: Optional[str] = Field(None, description="Server URL for online plugins (e.g., SonarQube).")
    token_env: Optional[str] = Field(None, description="Environment variable name for the plugin's authentication token.")
    # Generic fields for any plugin-specific settings
    settings: Dict[str, Any] = Field(default_factory=dict, description="Plugin-specific settings.")

# Define the overall configuration structure for .nvyzrc
class NvyzConfig(BaseModel):
    default_lang: str = Field(default="python", description="Default language for analysis if not specified.")
    parallel: int = Field(default=1, description="Default number of parallel processes for analysis.")
    exclude_patterns: List[str] = Field(default_factory=list, description="Global exclude patterns (globs).")
    mcp_url: Optional[str] = Field(None, description="URL for the Master Control Platform.")
    
    # Plugins configuration (e.g., codeql, sonarqube)
    plugins: Dict[str, PluginConfig] = Field(default_factory=dict)

    # General analyzer settings
    analyzers: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Configuration for native analyzers.")

# Default configuration instance
DEFAULT_CONFIG = NvyzConfig()

def get_config_path() -> Path:
    """Returns the path to the user's .nvyzrc configuration file."""
    # Use XDG Base Directory Specification on Linux/macOS or APPDATA on Windows
    if os.name == "nt":
        config_dir = Path(os.getenv("APPDATA")) / "nvyz"
    else:
        config_dir = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "nvyz"
    
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / ".nvyzrc.yaml" # Using .yaml extension for clarity

def load_config() -> NvyzConfig:
    """Loads the nvyz configuration from .nvyzrc.yaml."""
    config_path = get_config_path()
    if not config_path.is_file():
        return DEFAULT_CONFIG
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = yaml.safe_load(f)
        return NvyzConfig(**config_data)
    except (ValidationError, yaml.YAMLError, FileNotFoundError) as e:
        # Log error and return default config, or raise if strict
        print(f"Error loading configuration from {config_path}: {e}. Using default configuration.")
        return DEFAULT_CONFIG

def save_config(config: NvyzConfig):
    """Saves the nvyz configuration to .nvyzrc.yaml."""
    config_path = get_config_path()
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(config.model_dump(exclude_unset=True), f, indent=2, sort_keys=False)
    except Exception as e:
        print(f"Error saving configuration to {config_path}: {e}")

# Example usage (for testing)
if __name__ == "__main__":
    console.print("[blue]Testing NvyzConfig management...[/blue]")
    
    # Load (should be default or existing)
    current_config = load_config()
    console.print(f"Loaded config: {current_config.model_dump()}")

    # Modify
    current_config.default_lang = "javascript"
    current_config.plugins["codeql"] = PluginConfig(enabled=True, token_env="GITHUB_CODEQL_TOKEN")
    current_config.exclude_patterns.append("temp_files/")

    # Save
    save_config(current_config)
    console.print(f"Saved config: {current_config.model_dump()}")

    # Load again to verify
    reloaded_config = load_config()
    console.print(f"Reloaded config: {reloaded_config.model_dump()}")
    assert reloaded_config.default_lang == "javascript"
    assert reloaded_config.plugins["codeql"].enabled is True
    assert "temp_files/" in reloaded_config.exclude_patterns

    console.print("[green]Config testing complete.[/green]")
