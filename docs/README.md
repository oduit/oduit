# Documentation

This directory contains the Sphinx documentation for oduit.

## Building the Documentation

### Prerequisites

- Python 3.8+
- pip

### Quick Start

1. **Install documentation dependencies:**

   ```bash
   cd docs
   pip install -r requirements.txt
   ```

2. **Install oduit in development mode:**

   ```bash
   pip install -e ..
   ```

3. **Build the documentation:**

   ```bash
   # Using the build script (recommended)
   ./build.sh

   # Or using make
   make html

   # Or using sphinx-build directly
   sphinx-build -b html . _build/html
   ```

4. **View the documentation:**
   Open `_build/html/index.html` in your web browser.

### Development

For live reloading during development, install `sphinx-autobuild`:

```bash
pip install sphinx-autobuild
make livehtml
```

This will start a local server with automatic rebuilding when files change.

### Available Formats

- **HTML**: `make html` - Standard web documentation
- **PDF**: `make latexpdf` - Requires LaTeX installation
- **EPUB**: `make epub` - E-book format
- **Text**: `make text` - Plain text format

### Structure

```
docs/
├── conf.py              # Sphinx configuration
├── index.rst            # Main documentation page
├── installation.rst     # Installation guide
├── quickstart.rst       # Quick start guide
├── configuration.rst    # Configuration documentation
├── examples.rst         # Usage examples
├── changelog.rst        # Project changelog
├── api/                 # API documentation
│   ├── modules.rst      # Complete API reference
│   ├── process_manager.rst
│   ├── config_loader.rst
│   └── ...
├── _static/             # Static files (CSS, images)
├── _templates/          # Custom templates
├── requirements.txt     # Documentation dependencies
├── build.sh             # Build script
└── Makefile            # Make targets

```

### Adding New Documentation

1. Create new `.rst` files in the appropriate directory
2. Add them to the `toctree` in `index.rst` or relevant parent file
3. Use Sphinx directives for cross-references and code examples
4. Run the build to verify formatting

### API Documentation

API documentation is automatically generated from docstrings using Sphinx autodoc.
To add new modules:

1. Add the module to `api/modules.rst`
2. Create a dedicated file in `api/` for detailed documentation
3. Add usage examples and cross-references

### Troubleshooting

**Common Issues:**

- **Import errors**: Ensure oduit is installed in development mode (`pip install -e ..`)
- **Missing modules**: Check that all dependencies are installed (`pip install -r requirements.txt`)
- **Build errors**: Clean the build directory (`make clean`) and rebuild

**Getting Help:**

- Check the Sphinx documentation: https://www.sphinx-doc.org/
- For reStructuredText syntax: https://docutils.sourceforge.io/rst.html
