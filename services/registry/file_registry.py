import os
import json
import time
import uuid
import shutil
import hashlib
from pathlib import Path


class FileRegistry:
    def __init__(self, base_dir=None):
        """Initialize the file registry service"""
        if base_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        self.base_dir = base_dir
        self.registry_dir = os.path.join(base_dir, 'registry')

        # Create registry directory if it doesn't exist
        Path(self.registry_dir).mkdir(exist_ok=True)

        # Create storage directories
        self.files_dir = os.path.join(self.registry_dir, 'files')
        self.owners_dir = os.path.join(self.registry_dir, 'owners')
        Path(self.files_dir).mkdir(exist_ok=True)
        Path(self.owners_dir).mkdir(exist_ok=True)

        # Main registry file path
        self.registry_path = os.path.join(self.registry_dir, 'file_registry.json')

        # File details index path
        self.details_index_path = os.path.join(self.registry_dir, 'file_details_index.json')

        # Initialize registry if it doesn't exist
        if not os.path.exists(self.registry_path):
            self._init_registry()

        # Initialize details index if it doesn't exist
        if not os.path.exists(self.details_index_path):
            self._init_details_index()

        # Keep track of cached registry data to reduce disk reads
        self._registry_cache = None
        self._last_cache_time = 0
        self._cache_valid_seconds = 2  # Cache valid for 2 seconds

        # Keep track of cached details index
        self._details_index_cache = None
        self._details_last_cache_time = 0

    def _init_registry(self):
        """Initialize the registry with default structure"""
        default_registry = {
            "files": {},
            "owners": {},
            "metadata": {
                "created": time.time(),
                "last_updated": time.time(),
                "version": "1.0",
                "file_count": 0,
                "owner_count": 0
            }
        }
        self._save_registry(default_registry)

    def _init_details_index(self):
        """Initialize the file details index"""
        default_index = {
            "files_by_name": {},
            "files_by_hash": {},
            "files_by_owner": {},
            "shared_files": {},
            "metadata": {
                "created": time.time(),
                "last_updated": time.time(),
                "version": "1.0"
            }
        }
        self._save_details_index(default_index)

    def _get_registry(self, force_refresh=False):
        """Get the current registry data, using cache if available"""
        current_time = time.time()

        # If cache is valid and not forced to refresh, return cache
        if not force_refresh and self._registry_cache and current_time - self._last_cache_time < self._cache_valid_seconds:
            return self._registry_cache

        try:
            if not os.path.exists(self.registry_path):
                self._init_registry()

            with open(self.registry_path, 'r') as f:
                registry = json.load(f)

            # Update cache
            self._registry_cache = registry
            self._last_cache_time = current_time

            # Ensure proper structure
            if "files" not in registry:
                registry["files"] = {}
            if "owners" not in registry:
                registry["owners"] = {}
            if "metadata" not in registry:
                registry["metadata"] = {
                    "created": time.time(),
                    "last_updated": time.time(),
                    "version": "1.0",
                    "file_count": 0,
                    "owner_count": 0
                }

            return registry
        except Exception as e:
            print(f"Error reading registry: {str(e)}")
            # If there's an error, return a clean registry
            default_registry = {
                "files": {},
                "owners": {},
                "metadata": {
                    "created": time.time(),
                    "last_updated": time.time(),
                    "version": "1.0",
                    "file_count": 0,
                    "owner_count": 0
                }
            }
            self._registry_cache = default_registry
            self._last_cache_time = current_time
            return default_registry

    def _get_details_index(self, force_refresh=False):
        """Get the file details index, using cache if available"""
        current_time = time.time()

        # If cache is valid and not forced to refresh, return cache
        if not force_refresh and self._details_index_cache and current_time - self._details_last_cache_time < self._cache_valid_seconds:
            return self._details_index_cache

        try:
            if not os.path.exists(self.details_index_path):
                self._init_details_index()

            with open(self.details_index_path, 'r') as f:
                index = json.load(f)

            # Update cache
            self._details_index_cache = index
            self._details_last_cache_time = current_time

            # Ensure proper structure
            if "files_by_name" not in index:
                index["files_by_name"] = {}
            if "files_by_hash" not in index:
                index["files_by_hash"] = {}
            if "files_by_owner" not in index:
                index["files_by_owner"] = {}
            if "shared_files" not in index:
                index["shared_files"] = {}

            return index
        except Exception as e:
            print(f"Error reading details index: {str(e)}")
            # If there's an error, return a clean index
            self._init_details_index()
            return self._details_index_cache

    def _save_registry(self, registry):
        """Save registry data to disk"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)

            # Update last modified time
            if "metadata" in registry:
                registry["metadata"]["last_updated"] = time.time()
                # Update counts
                registry["metadata"]["file_count"] = len(registry.get("files", {}))
                registry["metadata"]["owner_count"] = len(registry.get("owners", {}))

            # Create a backup before writing
            if os.path.exists(self.registry_path):
                backup_path = f"{self.registry_path}.bak"
                shutil.copy2(self.registry_path, backup_path)

            with open(self.registry_path, 'w') as f:
                json.dump(registry, f, indent=2)

            # Update cache
            self._registry_cache = registry
            self._last_cache_time = time.time()

            return True
        except Exception as e:
            print(f"Error saving registry: {str(e)}")
            return False

    def _save_details_index(self, index):
        """Save file details index to disk"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.details_index_path), exist_ok=True)

            # Update last modified time
            if "metadata" in index:
                index["metadata"]["last_updated"] = time.time()

            # Create a backup before writing
            if os.path.exists(self.details_index_path):
                backup_path = f"{self.details_index_path}.bak"
                shutil.copy2(self.details_index_path, backup_path)

            with open(self.details_index_path, 'w') as f:
                json.dump(index, f, indent=2)

            # Update cache
            self._details_index_cache = index
            self._details_last_cache_time = time.time()

            return True
        except Exception as e:
            print(f"Error saving details index: {str(e)}")
            return False

    def _save_file_details(self, file_id, details):
        """Save detailed file information to a separate JSON file"""
        try:
            file_path = os.path.join(self.files_dir, f"{file_id}.json")
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            with open(file_path, 'w') as f:
                json.dump(details, f, indent=2)

            return True
        except Exception as e:
            print(f"Error saving file details for {file_id}: {str(e)}")
            return False

    def _get_file_details(self, file_id):
        """Get detailed file information from its JSON file"""
        try:
            file_path = os.path.join(self.files_dir, f"{file_id}.json")

            if not os.path.exists(file_path):
                return None

            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading file details for {file_id}: {str(e)}")
            return None

    def _calculate_file_hash(self, file_path):
        """Calculate a hash for a file to use as unique identifier"""
        try:
            if not os.path.exists(file_path):
                return None

            # Use a combination of file stats and partial content
            stat = os.stat(file_path)
            hash_input = f"{file_path}|{stat.st_size}|{stat.st_mtime}"

            # If it's not too large, also hash a portion of content
            if stat.st_size < 10_000_000:  # 10MB limit
                with open(file_path, 'rb') as f:
                    # Read first 8KB of file
                    content = f.read(8192)
                    hash_input += "|" + str(hashlib.md5(content).hexdigest())

            return hashlib.sha256(hash_input.encode()).hexdigest()
        except Exception as e:
            print(f"Error calculating file hash for {file_path}: {str(e)}")
            return None

    def register_file(self, filename, owner, file_type="standard", metadata=None, file_path=None):
        """Register a file with an owner"""
        if not filename or not owner:
            return False, "Filename and owner are required"

        try:
            registry = self._get_registry()
            details_index = self._get_details_index()

            # Generate a unique ID for the file if not already in registry
            file_id = None

            # Calculate file hash if path is provided
            file_hash = None
            if file_path and os.path.exists(file_path):
                file_hash = self._calculate_file_hash(file_path)

                # Check if we already have this file by hash
                if file_hash and details_index and "files_by_hash" in details_index and file_hash in details_index["files_by_hash"]:
                    file_id = details_index["files_by_hash"][file_hash]

            # If not found by hash, check by name and owner
            if not file_id:
                # First check if file already exists in registry
                for existing_id, file_info in registry["files"].items():
                    if file_info.get("filename") == filename and file_info.get("owner") == owner:
                        file_id = existing_id
                        break

            # Setup metadata if not provided
            if metadata is None:
                metadata = {}

            # Add file stats to metadata if path provided
            if file_path and os.path.exists(file_path):
                stat = os.stat(file_path)
                if "size" not in metadata:
                    metadata["size"] = stat.st_size
                if "modified" not in metadata:
                    metadata["modified"] = stat.st_mtime
                if "created" not in metadata:
                    metadata["created"] = stat.st_ctime

            # If file not found, create a new entry
            if not file_id:
                file_id = str(uuid.uuid4())
                current_time = time.time()

                # Create basic file entry for registry
                registry["files"][file_id] = {
                    "filename": filename,
                    "owner": owner,
                    "type": file_type,
                    "created": current_time,
                    "last_accessed": current_time,
                    "shared_with": []
                }

                # Create detailed file entry
                detailed_info = {
                    "file_id": file_id,
                    "filename": filename,
                    "owner": owner,
                    "type": file_type,
                    "created": current_time,
                    "last_accessed": current_time,
                    "last_modified": current_time,
                    "shared_with": [],
                    "metadata": metadata or {},
                    "file_hash": file_hash,
                    "access_history": [
                        {"action": "created", "timestamp": current_time, "user": owner}
                    ]
                }

                # Save detailed info to a separate file
                self._save_file_details(file_id, detailed_info)

                # Add to owner's files
                if owner not in registry["owners"]:
                    registry["owners"][owner] = {
                        "files": [],
                        "first_seen": current_time,
                        "last_activity": current_time
                    }

                if owner in registry["owners"] and file_id not in registry["owners"][owner]["files"]:
                    registry["owners"][owner]["files"].append(file_id)
                    registry["owners"][owner]["last_activity"] = current_time

                # Update indices
                if details_index and "files_by_name" in details_index:
                    details_index["files_by_name"][filename] = details_index["files_by_name"].get(filename, [])
                    if file_id not in details_index["files_by_name"][filename]:
                        details_index["files_by_name"][filename].append(file_id)

                if file_hash and details_index and "files_by_hash" in details_index:
                    details_index["files_by_hash"][file_hash] = file_id

                if details_index and "files_by_owner" in details_index:
                    if owner not in details_index["files_by_owner"]:
                        details_index["files_by_owner"][owner] = []
                    if file_id not in details_index["files_by_owner"][owner]:
                        details_index["files_by_owner"][owner].append(file_id)

                # Save updated registry and index
                self._save_registry(registry)
                if details_index:
                    self._save_details_index(details_index)

                return True, file_id
            else:
                # Update existing entry
                current_time = time.time()
                registry["files"][file_id]["last_accessed"] = current_time

                # Update owner's last activity
                if owner in registry.get("owners", {}):
                    registry["owners"][owner]["last_activity"] = current_time

                # Get existing details and update them
                detailed_info = self._get_file_details(file_id) or {}
                detailed_info["last_accessed"] = current_time
                detailed_info["access_history"] = detailed_info.get("access_history", [])
                detailed_info["access_history"].append({
                    "action": "accessed",
                    "timestamp": current_time,
                    "user": owner
                })

                # Update metadata
                if metadata:
                    detailed_info["metadata"] = detailed_info.get("metadata", {})
                    detailed_info["metadata"].update(metadata)

                # Save updated information
                self._save_file_details(file_id, detailed_info)
                self._save_registry(registry)

                return True, file_id

        except Exception as e:
            print(f"Error registering file: {str(e)}")
            return False, f"Error registering file: {str(e)}"

    def get_file_owner(self, filename):
        """Get the owner of a file"""
        try:
            # First check the index for faster lookup
            details_index = self._get_details_index()
            if details_index and "files_by_name" in details_index and filename in details_index["files_by_name"]:
                file_ids = details_index["files_by_name"][filename]
                if file_ids:
                    # Get the first file's details
                    file_details = self._get_file_details(file_ids[0])
                    if file_details:
                        return file_details.get("owner")

            # Fallback to searching the registry
            registry = self._get_registry()
            for file_id, file_info in registry["files"].items():
                if file_info.get("filename") == filename:
                    return file_info.get("owner")

            return None
        except Exception as e:
            print(f"Error getting file owner: {str(e)}")
            return None

    def get_file_by_id(self, file_id):
        """Get file information by ID"""
        try:
            # First try to get detailed information
            detailed_info = self._get_file_details(file_id)

            if detailed_info:
                # Update last accessed time
                current_time = time.time()
                detailed_info["last_accessed"] = current_time
                detailed_info["access_history"] = detailed_info.get("access_history", [])
                detailed_info["access_history"].append({
                    "action": "retrieved",
                    "timestamp": current_time
                })
                self._save_file_details(file_id, detailed_info)

                # Also update the registry
                registry = self._get_registry()
                if file_id in registry["files"]:
                    registry["files"][file_id]["last_accessed"] = current_time
                    self._save_registry(registry)

                return detailed_info

            # Fallback to registry if detailed info not found
            registry = self._get_registry()
            if file_id in registry["files"]:
                file_info = registry["files"][file_id]
                # Update last accessed time
                current_time = time.time()
                file_info["last_accessed"] = current_time
                self._save_registry(registry)
                return file_info

            return None
        except Exception as e:
            print(f"Error getting file by ID: {str(e)}")
            return None

    def get_file_by_name(self, filename, owner=None):
        """Get file information by name (and optionally owner)"""
        try:
            # First check the index for faster lookup
            details_index = self._get_details_index()

            if details_index and "files_by_name" in details_index and filename in details_index["files_by_name"]:
                file_ids = details_index["files_by_name"][filename]

                for file_id in file_ids:
                    # Get the detailed file info
                    file_details = self._get_file_details(file_id)

                    if file_details:
                        # If owner specified, check ownership
                        if owner is None or file_details.get("owner") == owner:
                            # Update access time
                            current_time = time.time()
                            file_details["last_accessed"] = current_time
                            file_details["access_history"] = file_details.get("access_history", [])
                            file_details["access_history"].append({
                                "action": "name_lookup",
                                "timestamp": current_time,
                                "user": owner or "system"
                            })
                            self._save_file_details(file_id, file_details)

                            # Also update registry
                            registry = self._get_registry()
                            if file_id in registry["files"]:
                                registry["files"][file_id]["last_accessed"] = current_time
                                self._save_registry(registry)

                            return file_id, file_details

            # Fallback to searching the registry
            registry = self._get_registry()
            for file_id, file_info in registry["files"].items():
                if file_info.get("filename") == filename:
                    if owner is None or file_info.get("owner") == owner:
                        # Update last accessed time
                        current_time = time.time()
                        file_info["last_accessed"] = current_time
                        self._save_registry(registry)

                        # Get detailed info if available
                        file_details = self._get_file_details(file_id)
                        if file_details:
                            return file_id, file_details
                        else:
                            return file_id, file_info

            return None, None
        except Exception as e:
            print(f"Error getting file by name: {str(e)}")
            return None, None

    def list_files_by_owner(self, owner):
        """List all files owned by a specific user"""
        try:
            # First check the index for faster lookup
            details_index = self._get_details_index()

            if details_index and "files_by_owner" in details_index and owner in details_index["files_by_owner"]:
                file_ids = details_index["files_by_owner"][owner]

                owner_files = []
                for file_id in file_ids:
                    # Get detailed file info
                    file_details = self._get_file_details(file_id)

                    if file_details:
                        owner_files.append(file_details)
                    else:
                        # Fallback to registry info
                        registry = self._get_registry()
                        if file_id in registry["files"]:
                            owner_files.append({
                                "file_id": file_id,
                                **registry["files"][file_id]
                            })

                # Record access in owner metadata
                registry = self._get_registry()
                if owner in registry["owners"]:
                    registry["owners"][owner]["last_activity"] = time.time()
                    self._save_registry(registry)

                return owner_files

            # Fallback to registry
            registry = self._get_registry()

            if owner not in registry["owners"]:
                return []

            owner_files = []
            for file_id in registry["owners"][owner]["files"]:
                if file_id in registry["files"]:
                    # Try to get detailed info first
                    file_details = self._get_file_details(file_id)
                    if file_details:
                        owner_files.append(file_details)
                    else:
                        owner_files.append({
                            "file_id": file_id,
                            **registry["files"][file_id]
                        })

            # Record access in owner metadata
            if owner in registry["owners"]:
                registry["owners"][owner]["last_activity"] = time.time()
                self._save_registry(registry)

            return owner_files
        except Exception as e:
            print(f"Error listing files by owner: {str(e)}")
            return []

    def list_all_files(self):
        """List all files in the registry"""
        try:
            registry = self._get_registry()

            all_files = []
            for file_id, file_info in registry["files"].items():
                # Try to get detailed info first
                file_details = self._get_file_details(file_id)
                if file_details:
                    all_files.append(file_details)
                else:
                    all_files.append({
                        "file_id": file_id,
                        **file_info
                    })

            # Sort files by last_accessed (most recently accessed first)
            all_files.sort(key=lambda x: x.get("last_accessed", 0), reverse=True)

            return all_files
        except Exception as e:
            print(f"Error listing all files: {str(e)}")
            return []

    def share_file(self, file_id, shared_with):
        """Mark a file as shared with another user"""
        try:
            registry = self._get_registry()

            if file_id not in registry["files"]:
                return False, "File not found"

            file_info = registry["files"][file_id]
            current_time = time.time()

            # Ensure registry and file_info are valid
            if registry is None or file_id not in registry.get("files", {}):
                 return False, "File not found in registry"
            file_info = registry["files"][file_id]

            # Add to shared_with list if not already there
            if "shared_with" not in file_info:
                file_info["shared_with"] = []

            # Ensure we're working with a list
            if not isinstance(file_info["shared_with"], list):
                file_info["shared_with"] = []

            if shared_with not in file_info["shared_with"]:
                file_info["shared_with"].append(shared_with)

                # Add share timestamp
                if "share_timestamps" not in file_info:
                    file_info["share_timestamps"] = {}

                file_info["share_timestamps"][shared_with] = current_time

                # Update file details too
                file_details = self._get_file_details(file_id)
                if file_details:
                    file_details["shared_with"] = file_details.get("shared_with", [])
                    if shared_with not in file_details["shared_with"]:
                        file_details["shared_with"].append(shared_with)

                    # Add share timestamps
                    file_details["share_timestamps"] = file_details.get("share_timestamps", {})
                    file_details["share_timestamps"][shared_with] = current_time

                    # Add to access history
                    file_details["access_history"] = file_details.get("access_history", [])
                    file_details["access_history"].append({
                        "action": "shared",
                        "timestamp": current_time,
                        "user": shared_with,
                        "shared_by": file_info.get("owner", "unknown")
                    })

                    # Save details
                    self._save_file_details(file_id, file_details)

                # Save updated registry
                self._save_registry(registry)

                # Update index to show this file is shared with the user
                details_index = self._get_details_index()
                if details_index is None:
                    # Log an error but don\'t fail the share operation if index update fails
                    print(f"Warning: Could not load details index to update shared file for {shared_with}")
                else:
                    if "shared_files" not in details_index:
                        details_index["shared_files"] = {}
                    if shared_with not in details_index["shared_files"]:
                        details_index["shared_files"][shared_with] = []
                    if file_id not in details_index["shared_files"][shared_with]:
                        details_index["shared_files"][shared_with].append(file_id)
                    self._save_details_index(details_index)

            return True, "File shared successfully"
        except Exception as e:
            print(f"Error sharing file: {str(e)}")
            return False, f"Error sharing file: {str(e)}"\

    def unshare_file(self, file_id, shared_with):
        """Remove a user from file's shared_with list"""
        try:
            registry = self._get_registry()

            if file_id not in registry["files"]:
                return False, "File not found"

            file_info = registry["files"][file_id]

            # Remove from shared_with list
            if "shared_with" in file_info and shared_with in file_info["shared_with"]:
                file_info["shared_with"].remove(shared_with)

                # Remove share timestamp
                if "share_timestamps" in file_info and shared_with in file_info["share_timestamps"]:
                    del file_info["share_timestamps"][shared_with]

                # Save updated registry
                self._save_registry(registry)

            return True, "File unshared successfully"
        except Exception as e:
            print(f"Error unsharing file: {str(e)}")
            return False, f"Error unsharing file: {str(e)}"

    def list_files_shared_with_user(self, username):
        """List all files shared with a specific user"""
        try:
            # First check the index for faster lookup
            details_index = self._get_details_index()

            shared_files = []
            if details_index and "shared_files" in details_index and username in details_index["shared_files"]:
                file_ids = details_index["shared_files"][username]

                for file_id in file_ids:
                    # Get detailed file info
                    file_details = self._get_file_details(file_id)

                    if file_details:
                        # Create shared info with is_owner flag
                        shared_info = {
                            **file_details,
                            "is_owner": False
                        }

                        # Add share timestamp if available
                        if "share_timestamps" in file_details and username in file_details["share_timestamps"]:
                            shared_info["date_shared"] = file_details["share_timestamps"][username]

                        shared_files.append(shared_info)
                    else:
                        # Fallback to registry info
                        registry = self._get_registry()
                        if file_id in registry["files"]:
                            file_info = registry["files"][file_id]
                            shared_info = {
                                "file_id": file_id,
                                **file_info,
                                "is_owner": False
                            }

                            # Add share timestamp if available
                            if "share_timestamps" in file_info and username in file_info["share_timestamps"]:
                                shared_info["date_shared"] = file_info["share_timestamps"][username]

                            shared_files.append(shared_info)

                return shared_files

            # Fallback to registry search
            registry = self._get_registry()

            for file_id, file_info in registry["files"].items():
                if "shared_with" in file_info and username in file_info["shared_with"]:
                    # Try to get detailed info first
                    file_details = self._get_file_details(file_id)

                    if file_details:
                        shared_info = {
                            **file_details,
                            "is_owner": False
                        }
                    else:
                        shared_info = {
                            "file_id": file_id,
                            **file_info,
                            "is_owner": False
                        }

                    # Add share timestamp if available
                    share_timestamps = {}
                    if file_details and "share_timestamps" in file_details:
                        share_timestamps = file_details["share_timestamps"]
                    elif "share_timestamps" in file_info:
                        share_timestamps = file_info["share_timestamps"]

                    # Add share timestamp if available
                    share_timestamps = {}
                    if file_details and "share_timestamps" in file_details:
                        share_timestamps = file_details["share_timestamps"]
                    elif "share_timestamps" in file_info:
                        share_timestamps = file_info["share_timestamps"]

                    if username in share_timestamps:
                        shared_info["date_shared"] = share_timestamps[username]

                    shared_files.append(shared_info)

            return shared_files
        except Exception as e:
            print(f"Error listing shared files: {str(e)}")
            return []

    def update_file_metadata(self, file_id, metadata):
        """Update metadata for a file"""
        try:
            registry = self._get_registry()

            if file_id not in registry["files"]:
                return False, "File not found"

            file_info = registry["files"][file_id]

            # Create metadata field if it doesn't exist
            if "metadata" not in file_info:
                file_info["metadata"] = {}

            # Update metadata
            file_info["metadata"].update(metadata)

            # Update last accessed time
            file_info["last_accessed"] = time.time()

            # Save updated registry
            self._save_registry(registry)

            return True, "Metadata updated"
        except Exception as e:
            print(f"Error updating file metadata: {str(e)}")
            return False, f"Error updating file metadata: {str(e)}"

    def delete_file(self, file_id):
        """Remove a file from the registry"""
        try:
            registry = self._get_registry()

            if file_id not in registry["files"]:
                return False, "File not found"

            # Get owner before deleting
            owner = registry["files"][file_id].get("owner")

            # Remove from files
            del registry["files"][file_id]

            # Remove from owner's files list
            if owner and owner in registry["owners"] and "files" in registry["owners"][owner]:
                if file_id in registry["owners"][owner]["files"]:
                    registry["owners"][owner]["files"].remove(file_id)

            # Save updated registry
            self._save_registry(registry)

            return True, "File deleted from registry"
        except Exception as e:
            print(f"Error deleting file: {str(e)}")
            return False, f"Error deleting file: {str(e)}"

    def scan_directory_and_register(self, directory_path, owner, file_type="standard"):
        """Scan a directory and register all files with the given owner"""
        try:
            if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
                return False, "Directory not found"

            success_count = 0
            errors = []
            registered_files = []

            for filename in os.listdir(directory_path):
                file_path = os.path.join(directory_path, filename)

                if os.path.isfile(file_path):
                    # Get file metadata
                    stat = os.stat(file_path)
                    metadata = {
                        "size": stat.st_size,
                        "created": stat.st_ctime,
                        "modified": stat.st_mtime,
                        "scan_date": time.time(),
                        "source_directory": directory_path
                    }

                    # Calculate file hash
                    file_hash = self._calculate_file_hash(file_path)
                    if file_hash:
                        metadata["file_hash"] = file_hash

                    # Register file
                    success, result = self.register_file(
                        filename,
                        owner,
                        file_type,
                        metadata,
                        file_path
                    )

                    if success:
                        success_count += 1
                        registered_files.append({
                            "filename": filename,
                            "file_id": result,
                            "size": metadata["size"],
                            "hash": file_hash
                        })
                    else:
                        errors.append(f"Failed to register {filename}: {result}")

            return True, {
                "message": f"Registered {success_count} files with {len(errors)} errors",
                "success_count": success_count,
                "error_count": len(errors),
                "errors": errors,
                "registered_files": registered_files
            }
        except Exception as e:
            print(f"Error scanning directory: {str(e)}")
