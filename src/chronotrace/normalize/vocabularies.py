"""Controlled vocabularies for actions, action classes, and timestamp types."""

from typing import Set

VALID_TIMESTAMP_TYPES: Set[str] = {
    "created",
    "modified",
    "accessed",
    "changed",
    "deleted",
    "executed",
    "logged",
    "connected",
    "disconnected",
    "created_key",
    "last_write",
    "installed",
    "sent",
    "received",
    "boot",
    "shutdown",
    "inferred",
}

VALID_ACTION_CLASSES: Set[str] = {
    "file",
    "process",
    "network",
    "auth",
    "config",
    "system",
    "media",
    "other",
}

VALID_ACTIONS: Set[str] = {
    # File actions
    "FILE_CREATE",
    "FILE_WRITE",
    "FILE_READ",
    "FILE_DELETE",
    "FILE_RENAME",
    "FILE_ATTR_CHANGE",
    "FILE_TIMESTOMP",
    "FILE_ACCESS",
    # Process actions
    "PROCESS_START",
    "PROCESS_STOP",
    "SERVICE_INSTALL",
    "SCHEDULED_TASK_CREATE",
    "MODULE_LOAD",
    # Auth actions
    "AUTH_LOGIN",
    "AUTH_LOGOUT",
    "AUTH_FAIL",
    "USER_CREATE",
    "USER_DELETE",
    "PRIVILEGE_USE",
    # Network / Web
    "NETWORK_CONNECT",
    "NETWORK_DISCONNECT",
    "DNS_QUERY",
    "WEB_VISIT",
    # Config / Registry
    "REGISTRY_SET",
    "REGISTRY_DELETE",
    "CONFIG_CHANGE",
    # System
    "SYSTEM_BOOT",
    "SYSTEM_SHUTDOWN",
    "DEVICE_ATTACH",
    "DEVICE_DETACH",
    "LOG_CLEARED",
}
