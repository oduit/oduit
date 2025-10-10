#!/usr/bin/env python3
from oduit.module_manager import ModuleManager

addons_path = "tmp/myaddons"
manager = ModuleManager(addons_path)

collection = manager.find_modules()

print(f"Found {len(collection)} modules:")
for addon_name, manifest in collection.items():
    print(f"  - {addon_name}: {manifest.name} v{manifest.version}")
    print(f"    Codependencies: {', '.join(manifest.codependencies)}")

print(f"\nAll dependencies: {collection.get_all_dependencies()}")

print(f"\nInstallable addons: {collection.get_installable_addons()}")
