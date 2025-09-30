#!/bin/bash

# Build script for oduit documentation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building oduit documentation...${NC}"

# Navigate to docs directory
cd "$(dirname "$0")"

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo -e "${YELLOW}Installing documentation requirements...${NC}"
pip install -r requirements.txt

# Install the package in development mode
echo -e "${YELLOW}Installing oduit in development mode...${NC}"
pip install -e ..

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
rm -rf _build/

# Build documentation
echo -e "${YELLOW}Building HTML documentation...${NC}"
sphinx-build -b html . _build/html

# Build PDF documentation (if latex is available)
if command -v pdflatex &> /dev/null; then
    echo -e "${YELLOW}Building PDF documentation...${NC}"
    sphinx-build -b latex . _build/latex
    cd _build/latex
    make
    cd ../..
else
    echo -e "${YELLOW}pdflatex not found, skipping PDF build${NC}"
fi

echo -e "${GREEN}Documentation build complete!${NC}"
echo -e "${GREEN}HTML documentation: _build/html/index.html${NC}"
if [ -f "_build/latex/oduit.pdf" ]; then
    echo -e "${GREEN}PDF documentation: _build/latex/oduit.pdf${NC}"
fi
