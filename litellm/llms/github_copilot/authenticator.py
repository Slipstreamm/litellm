import json
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

import httpx

from litellm._logging import verbose_logger
from litellm.llms.custom_httpx.http_handler import _get_httpx_client

from .common_utils import (
    APIKeyExpiredError,
    AuthManagerError,
    GetAccessTokenError,
    GetAPIKeyError,
    GetDeviceCodeError,
    RefreshAPIKeyError,
)

# Constants
GITHUB_CLIENT_ID = "Iv1.b507a08c87ecfe98"
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_KEY_URL = "https://api.github.com/copilot_internal/v2/token"


class _GithubCopilotAuth:
    def _get_github_headers(self, access_token: Optional[str] = None) -> Dict[str, str]:
        """
        Generate standard GitHub headers for API requests.
        """
        headers = {
            "accept": "application/json",
            "editor-version": "vscode/1.85.1",
            "editor-plugin-version": "copilot/1.155.0",
            "user-agent": "GithubCopilot/1.155.0",
            "accept-encoding": "gzip,deflate,br",
        }
        if access_token:
            headers["authorization"] = f"token {access_token}"
        if "content-type" not in headers:
            headers["content-type"] = "application/json"
        return headers

    def _refresh_api_key(self, access_token: str) -> Dict[str, Any]:
        """
        Refresh the API key using the access token.
        """
        headers = self._get_github_headers(access_token)
        max_retries = 3
        for attempt in range(max_retries):
            try:
                sync_client = _get_httpx_client()
                response = sync_client.get(GITHUB_API_KEY_URL, headers=headers)
                response.raise_for_status()
                response_json = response.json()
                if "token" in response_json:
                    return response_json
            except httpx.HTTPStatusError as e:
                if attempt == max_retries - 1:
                    raise RefreshAPIKeyError(
                        message=f"Failed to refresh API key: {str(e)}",
                        status_code=e.response.status_code,
                    )
            except Exception as e:
                if attempt == max_retries - 1:
                    raise RefreshAPIKeyError(
                        message=f"Failed to refresh API key: {str(e)}", status_code=500
                    )
        raise RefreshAPIKeyError(
            message="Failed to refresh API key after maximum retries", status_code=500
        )


class GithubCopilotAuthManager(_GithubCopilotAuth):
    def start_login(self) -> Dict[str, str]:
        """
        Starts the device code login flow for GitHub Copilot.

        Returns:
            Dict[str, str]: A dictionary containing the device code, user code, and verification URI.
        """
        try:
            return self._get_device_code()
        except GetDeviceCodeError as e:
            raise AuthManagerError(
                message=f"Failed to start login: {e}", status_code=e.status_code
            )

    def poll_for_token(self, device_code: str) -> Dict[str, Any]:
        """
        Polls for the access token and then fetches the API key.

        Args:
            device_code (str): The device code from start_login.

        Returns:
            Dict[str, Any]: A dictionary containing the access_token and api_key_info.
        """
        try:
            access_token = self._poll_for_access_token(device_code)
            api_key_info = self._refresh_api_key(access_token)
            return {"access_token": access_token, "api_key_info": api_key_info}
        except (GetAccessTokenError, RefreshAPIKeyError) as e:
            raise AuthManagerError(
                message=f"Failed to get token: {e}", status_code=e.status_code
            )

    def _get_device_code(self) -> Dict[str, str]:
        """
        Get a device code for GitHub authentication.
        """
        try:
            sync_client = _get_httpx_client()
            resp = sync_client.post(
                GITHUB_DEVICE_CODE_URL,
                headers=self._get_github_headers(),
                json={"client_id": GITHUB_CLIENT_ID, "scope": "read:user"},
            )
            resp.raise_for_status()
            resp_json = resp.json()

            required_fields = ["device_code", "user_code", "verification_uri"]
            if not all(field in resp_json for field in required_fields):
                raise GetDeviceCodeError(
                    message="Response missing required fields",
                    status_code=400,
                )
            return resp_json
        except httpx.HTTPStatusError as e:
            raise GetDeviceCodeError(
                message=f"Failed to get device code: {str(e)}",
                status_code=e.response.status_code,
            )
        except Exception as e:
            raise GetDeviceCodeError(
                message=f"Failed to get device code: {str(e)}", status_code=500
            )

    def _poll_for_access_token(self, device_code: str) -> str:
        """
        Poll for an access token after user authentication.
        """
        sync_client = _get_httpx_client()
        max_attempts = 12  # 1 minute (12 * 5 seconds)

        for attempt in range(max_attempts):
            try:
                resp = sync_client.post(
                    GITHUB_ACCESS_TOKEN_URL,
                    headers=self._get_github_headers(),
                    json={
                        "client_id": GITHUB_CLIENT_ID,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                )
                resp.raise_for_status()
                resp_json = resp.json()

                if "access_token" in resp_json:
                    return resp_json["access_token"]
                elif (
                    "error" in resp_json
                    and resp_json.get("error") == "authorization_pending"
                ):
                    time.sleep(5)
                    continue
                else:
                    raise GetAccessTokenError(
                        message=f"Unexpected response: {resp_json}", status_code=400
                    )
            except httpx.HTTPStatusError as e:
                raise GetAccessTokenError(
                    message=f"Failed to get access token: {str(e)}",
                    status_code=e.response.status_code,
                )
            except Exception as e:
                raise GetAccessTokenError(
                    message=f"Failed to get access token: {str(e)}", status_code=500
                )

        raise GetAccessTokenError(
            message="Timed out waiting for user to authorize the device",
            status_code=408,
        )


class Authenticator(_GithubCopilotAuth):
    def __init__(self, auth_info: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the GitHub Copilot authenticator."""
        self.auth_info = auth_info
        self.token_dir = os.getenv(
            "GITHUB_COPILOT_TOKEN_DIR",
            os.path.expanduser("~/.config/litellm/github_copilot"),
        )
        self.access_token_file = os.path.join(
            self.token_dir,
            os.getenv("GITHUB_COPILOT_ACCESS_TOKEN_FILE", "access-token"),
        )
        self.api_key_file = os.path.join(
            self.token_dir, os.getenv("GITHUB_COPILOT_API_KEY_FILE", "api-key.json")
        )
        if not auth_info:
            self._ensure_token_dir()

    def get_access_token(self) -> str:
        """
        Get the GitHub access token.
        """
        if self.auth_info and "access_token" in self.auth_info:
            return self.auth_info["access_token"]

        try:
            with open(self.access_token_file, "r") as f:
                return f.read().strip()
        except IOError:
            raise GetAccessTokenError(
                message="Access token not provided and not found in file. Please run `litellm --github_copilot_login`",
                status_code=401,
            )

    def get_api_key(self) -> str:
        """
        Get the API key, refreshing if necessary.
        """
        if self.auth_info and "api_key_info" in self.auth_info:
            api_key_info = self.auth_info["api_key_info"]
            if api_key_info.get("expires_at", 0) > datetime.now().timestamp():
                token = api_key_info.get("token")
                if token:
                    return token

            # API key expired, refresh it
            access_token = self.get_access_token()
            new_api_key_info = self._refresh_api_key(access_token)
            self.auth_info["api_key_info"] = new_api_key_info
            token = new_api_key_info.get("token")
            if not token:
                raise GetAPIKeyError(message="API key response missing token", status_code=500)
            return token

        # Fallback to file-based storage
        try:
            with open(self.api_key_file, "r") as f:
                api_key_info = json.load(f)
                if api_key_info.get("expires_at", 0) > datetime.now().timestamp():
                    token = api_key_info.get("token")
                    if token:
                        return token
        except (IOError, json.JSONDecodeError, KeyError):
            pass  # Will try to refresh below

        try:
            access_token = self.get_access_token()
            api_key_info = self._refresh_api_key(access_token)
            with open(self.api_key_file, "w") as f:
                json.dump(api_key_info, f)
            token = api_key_info.get("token")
            if not token:
                raise GetAPIKeyError(message="API key response missing token", status_code=500)
            return token
        except (RefreshAPIKeyError, IOError) as e:
            raise GetAPIKeyError(
                message=f"Failed to get or refresh API key: {str(e)}",
                status_code=500,
            )

    def _ensure_token_dir(self) -> None:
        """Ensure the token directory exists."""
        if not os.path.exists(self.token_dir):
            os.makedirs(self.token_dir, exist_ok=True)
