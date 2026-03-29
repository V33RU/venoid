"""Core APK parser using androguard for manifest and DEX analysis."""

from pathlib import Path
from typing import Optional, List, Dict, Any
import logging

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.misc import AnalyzeAPK

logger = logging.getLogger(__name__)

# Android manifest namespace constant
ANDROID_NS = "http://schemas.android.com/apk/res/android"


class APKParser:
    """Parse APK files to extract manifest info, components, and DEX data."""

    def __init__(self, apk_path: str) -> None:
        """Initialize parser with APK path.

        Args:
            apk_path: Path to the APK file to analyze.
        """
        self.apk_path = Path(apk_path)
        self.apk: Optional[APK] = None
        self.dexes: List[DEX] = []
        self.analysis: Any = None
        self._manifest_xml: Any = None

    def load(self) -> bool:
        """Load and parse the APK file.

        Returns:
            True if loading was successful, False otherwise.
        """
        try:
            if not self.apk_path.exists():
                logger.error(f"APK file not found: {self.apk_path}")
                return False

            self.apk, self.dexes, self.analysis = AnalyzeAPK(str(self.apk_path))
            logger.info(f"Successfully loaded APK: {self.apk_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load APK: {e}")
            return False

    def get_package_name(self) -> str:
        """Get the package name from the manifest.

        Returns:
            Package name or empty string if not available.
        """
        if self.apk:
            return self.apk.get_package() or ""
        return ""

    def get_min_sdk(self) -> int:
        """Get the minimum SDK version.

        Returns:
            Minimum SDK version or 0 if not available.
        """
        if self.apk:
            try:
                return int(self.apk.get_min_sdk_version() or 0)
            except (ValueError, TypeError):
                return 0
        return 0

    def get_target_sdk(self) -> int:
        """Get the target SDK version.

        Returns:
            Target SDK version or 0 if not available.
        """
        if self.apk:
            try:
                return int(self.apk.get_target_sdk_version() or 0)
            except (ValueError, TypeError):
                return 0
        return 0

    def _get_components(self, component_type: str, getter_name: str,
                        extra_attrs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get components of a given type from the manifest.

        Args:
            component_type: XML tag name (activity, service, receiver, provider).
            getter_name: Name of the APK method to list components.
            extra_attrs: Additional manifest attributes to include.

        Returns:
            List of component definitions.
        """
        if not self.apk:
            return []

        components = []
        for name in getattr(self.apk, getter_name)():
            entry: Dict[str, Any] = {
                'name': name,
                'exported': self._is_exported(component_type, name),
                'permission': self.get_manifest_element(component_type, 'permission', name),
                'intent_filters': self._get_intent_filters(component_type, name),
            }
            for attr in (extra_attrs or []):
                entry[attr] = self.get_manifest_element(component_type, attr, name)
            components.append(entry)
        return components

    def get_activities(self) -> List[Dict[str, Any]]:
        """Get all activities from the manifest."""
        return self._get_components('activity', 'get_activities')

    def get_services(self) -> List[Dict[str, Any]]:
        """Get all services from the manifest."""
        return self._get_components('service', 'get_services')

    def get_receivers(self) -> List[Dict[str, Any]]:
        """Get all broadcast receivers from the manifest."""
        return self._get_components('receiver', 'get_receivers')

    def get_providers(self) -> List[Dict[str, Any]]:
        """Get all content providers from the manifest."""
        providers = self._get_components('provider', 'get_providers', extra_attrs=[
            'readPermission', 'writePermission', 'grantUriPermissions',
        ])
        # Add authorities (needs special handling)
        for p in providers:
            p['authorities'] = self._get_provider_authorities(p['name'])
        return providers

    def _is_exported(self, component_type: str, name: str) -> bool:
        """Check if a component is exported.

        Args:
            component_type: Type of component (activity, service, etc.)
            name: Component name.

        Returns:
            True if exported, False otherwise.
        """
        if not self.apk:
            return False

        exported = self.get_manifest_element(component_type, 'exported', name)
        if exported is not None:
            return exported.lower() == 'true'

        # API <= 30: component with intent-filter is auto-exported
        has_intent_filter = len(self._get_intent_filters(component_type, name)) > 0
        return has_intent_filter

    def _get_intent_filters(self, component_type: str, name: str) -> List[Dict[str, List[str]]]:
        """Get intent filters for a component.

        Args:
            component_type: Type of component.
            name: Component name.

        Returns:
            List of intent filter dictionaries.
        """
        filters = []
        if not self.apk:
            return filters

        xml = self.apk.get_android_manifest_xml()
        if xml is None:
            return filters

        for elem in xml.iter():
            if elem.tag == component_type:
                elem_name = elem.get(f'{{{ANDROID_NS}}}name')
                if elem_name == name or (name.count('.') == 0 and elem_name.endswith(f".{name}")):
                    for intent_filter in elem.findall('.//intent-filter'):
                        auto_verify = intent_filter.get(f'{{{ANDROID_NS}}}autoVerify', 'false')
                        filter_data = {
                            'actions': [],
                            'categories': [],
                            'data': [],
                            'autoVerify': auto_verify.lower() == 'true'
                        }
                        for action in intent_filter.findall('.//action'):
                            action_name = action.get(f'{{{ANDROID_NS}}}name')
                            if action_name:
                                filter_data['actions'].append(action_name)
                        for category in intent_filter.findall('.//category'):
                            cat_name = category.get(f'{{{ANDROID_NS}}}name')
                            if cat_name:
                                filter_data['categories'].append(cat_name)
                        for data in intent_filter.findall('.//data'):
                            spec = {}
                            for attr in ['scheme', 'host', 'path', 'pathPrefix', 'pathPattern']:
                                val = data.get(f'{{{ANDROID_NS}}}{attr}')
                                if val:
                                    spec[attr] = val
                            if spec:
                                filter_data['data'].append(spec)
                        filters.append(filter_data)
        return filters

    def _get_provider_authorities(self, name: str) -> List[str]:
        """Get authorities for a content provider.

        Args:
            name: Provider name.

        Returns:
            List of authority strings.
        """
        if not self.apk:
            return []

        authorities = self.get_manifest_element('provider', 'authorities', name)
        if authorities:
            return authorities.split(';')
        return []

    def get_permissions(self) -> List[str]:
        """Get all permissions declared or used by the app.

        Returns:
            List of permission strings.
        """
        if self.apk:
            return self.apk.get_permissions() or []
        return []

    def get_custom_permissions(self) -> List[Dict[str, str]]:
        """Get custom permissions defined by the app.

        Returns:
            List of permission definitions with name and protection level.
        """
        custom_perms = []
        if not self.apk:
            return custom_perms

        xml = self.apk.get_android_manifest_xml()
        if xml is None:
            return custom_perms

        for perm in xml.iter('permission'):
            name = perm.get(f'{{{ANDROID_NS}}}name')
            protection = perm.get(f'{{{ANDROID_NS}}}protectionLevel', 'normal')
            if name:
                custom_perms.append({'name': name, 'protectionLevel': protection})
        return custom_perms

    def get_android_manifest_xml(self):
        """Get the parsed AndroidManifest.xml (cached after first call).

        Returns:
            XML element tree or None if not available.
        """
        if self._manifest_xml is None and self.apk:
            self._manifest_xml = self.apk.get_android_manifest_xml()
        return self._manifest_xml

    def get_apk(self):
        """Get the underlying APK object.

        Returns:
            APK object or None.
        """
        return self.apk

    def get_manifest_element(self, tag: str, attribute: str, name: str) -> Optional[str]:
        """Get an element attribute from manifest.

        Args:
            tag: XML tag name.
            attribute: Attribute name without namespace.
            name: Component name.

        Returns:
            Attribute value or None.
        """
        if not self.apk:
            return None

        xml = self.get_android_manifest_xml()
        if xml is None:
            return None

        ns = ANDROID_NS

        for elem in xml.iter(tag):
            elem_name = elem.get(f'{{{ns}}}name', '')
            if elem_name == name or elem_name == f".{name.split('.')[-1]}":
                return elem.get(f'{{{ns}}}{attribute}')
        return None

    def get_file_provider_paths(self, provider_name: str) -> Optional[bytes]:
        """Return the raw bytes of the FileProvider paths XML for *provider_name*.

        Looks for a <meta-data android:name="android.support.FILE_PROVIDER_PATHS">
        element inside the provider declaration and tries to read the referenced
        XML resource file from the APK.  Falls back to scanning common file names.

        Returns:
            Raw XML bytes if found, else None.
        """
        if not self.apk:
            return None

        xml = self.get_android_manifest_xml()
        if xml is None:
            return None

        ns = ANDROID_NS
        resource_file: Optional[str] = None

        # Locate the provider element and its FILE_PROVIDER_PATHS meta-data
        for elem in xml.iter("provider"):
            elem_name = elem.get(f"{{{ns}}}name", "")
            if elem_name != provider_name and not elem_name.endswith(provider_name.split(".")[-1]):
                continue
            for meta in elem.findall("meta-data"):
                meta_name = meta.get(f"{{{ns}}}name", "")
                if "FILE_PROVIDER_PATHS" in meta_name or meta_name in (
                    "android.support.FILE_PROVIDER_PATHS",
                    "androidx.core.content.FileProvider",
                ):
                    resource_val = meta.get(f"{{{ns}}}resource", "")
                    # resource_val is "@xml/something" or a compiled resource int
                    if resource_val.startswith("@xml/"):
                        resource_file = "res/xml/" + resource_val[len("@xml/"):] + ".xml"
                    elif resource_val.startswith("@"):
                        # Compiled resource - try common names below
                        pass
            break

        # Try the resolved name first, then fall back to common guesses
        candidates = []
        if resource_file:
            candidates.append(resource_file)
        candidates.extend([
            "res/xml/file_paths.xml",
            "res/xml/provider_paths.xml",
            "res/xml/filepaths.xml",
            "res/xml/paths.xml",
            "res/xml/file_provider_paths.xml",
        ])

        for candidate in candidates:
            try:
                data = self.apk.get_file(candidate)
                if data:
                    return data
            except Exception:
                continue

        return None
