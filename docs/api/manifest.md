# Manifest

The Manifest class represents an Odoo module manifest (\_\_manifest\_\_.py).

```{eval-rst}
.. automodule:: oduit.manifest
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:
```

## Class Reference

```{eval-rst}
.. autoclass:: oduit.manifest.Manifest
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:
```

## Exceptions

```{eval-rst}
.. autoexception:: oduit.manifest.ManifestError
   :show-inheritance:
   :no-index:
```

```{eval-rst}
.. autoexception:: oduit.manifest.InvalidManifestError
   :show-inheritance:
   :no-index:
```

```{eval-rst}
.. autoexception:: oduit.manifest.ManifestNotFoundError
   :show-inheritance:
   :no-index:
```

## Usage Examples

### Basic Manifest Operations

```python
from oduit.manifest import Manifest

# Load manifest from a module directory
manifest = Manifest('/path/to/module')

# Access manifest properties
print(f"Name: {manifest.name}")
print(f"Version: {manifest.version}")
print(f"Installable: {manifest.installable}")
print(f"Auto-install: {manifest.auto_install}")

# Get codependencies
codeps = manifest.codependencies
print(f"Codependencies: {codeps}")

# Check for specific dependency
has_sale = manifest.has_dependency('sale')
print(f"Depends on sale: {has_sale}")
```

### Creating Manifest from Dict

```python
# Create manifest from dictionary (useful for testing)
manifest_data = {
    'name': 'My Module',
    'version': '1.0.0',
    'depends': ['base', 'sale'],
    'installable': True,
}
manifest = Manifest.from_dict(manifest_data, module_name='my_module')
```

### Validating Manifest

```python
# Validate manifest structure
warnings = manifest.validate_structure()
if warnings:
    print("Validation warnings:")
    for warning in warnings:
        print(f"  - {warning}")

# Get raw manifest data
raw_data = manifest.get_raw_data()
print(f"Raw data: {raw_data}")
```
