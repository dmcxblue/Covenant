#!/bin/bash

# Covenant Build Script
# Builds the Covenant C2 framework

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/Covenant"
SOLUTION_FILE="$SCRIPT_DIR/Covenant.sln"
DATA_DIR="$PROJECT_DIR/Data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[x]${NC} $1"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build Options:"
    echo "  -b, --build       Build the project (default)"
    echo "  -r, --release     Build in Release mode"
    echo "  -c, --clean       Clean before building"
    echo "  -p, --publish     Publish the project"
    echo "  -o, --output DIR  Output directory for publish (default: ./out)"
    echo "  -R, --run         Run after building"
    echo ""
    echo "Reset Options:"
    echo "  -x, --reset       Delete database for fresh start (requires new registration)"
    echo "  -P, --purge       Full purge: delete bin, obj, database, temp files, and certs"
    echo ""
    echo "Other:"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Debug build"
    echo "  $0 -r                 # Release build"
    echo "  $0 -c -r              # Clean and release build"
    echo "  $0 -p -o ./publish    # Publish to ./publish"
    echo "  $0 -r -R              # Release build and run"
    echo "  $0 -x -r -R           # Reset database, release build, and run"
    echo "  $0 -P -r              # Full purge and release build"
}

# Default values
BUILD=true
RELEASE=false
CLEAN=false
PUBLISH=false
RUN=false
RESET=false
PURGE=false
OUTPUT_DIR="$SCRIPT_DIR/out"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--build)
            BUILD=true
            shift
            ;;
        -r|--release)
            RELEASE=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -p|--publish)
            PUBLISH=true
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -R|--run)
            RUN=true
            shift
            ;;
        -x|--reset)
            RESET=true
            shift
            ;;
        -P|--purge)
            PURGE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set configuration
if [ "$RELEASE" = true ]; then
    CONFIG="Release"
else
    CONFIG="Debug"
fi

print_status "Covenant Build Script"
echo "================================"

# Full purge if requested
if [ "$PURGE" = true ]; then
    print_warning "Performing full purge..."

    # Delete bin and obj directories
    if [ -d "$PROJECT_DIR/bin" ]; then
        rm -rf "$PROJECT_DIR/bin"
        print_status "Deleted bin directory"
    fi
    if [ -d "$PROJECT_DIR/obj" ]; then
        rm -rf "$PROJECT_DIR/obj"
        print_status "Deleted obj directory"
    fi

    # Delete database and SQLite lock files
    if [ -f "$DATA_DIR/covenant.db" ]; then
        rm -f "$DATA_DIR/covenant.db" "$DATA_DIR/covenant.db-journal" "$DATA_DIR/covenant.db-shm" "$DATA_DIR/covenant.db-wal"
        print_status "Deleted database (covenant.db and lock files)"
    fi

    # Delete certificates
    if [ -f "$DATA_DIR/covenant-dev-private.pfx" ]; then
        rm -f "$DATA_DIR/covenant-dev-private.pfx"
        print_status "Deleted private certificate"
    fi
    if [ -f "$DATA_DIR/covenant-dev-public.cer" ]; then
        rm -f "$DATA_DIR/covenant-dev-public.cer"
        print_status "Deleted public certificate"
    fi

    # Delete temp directory contents
    if [ -d "$DATA_DIR/Temp" ]; then
        rm -rf "$DATA_DIR/Temp"/*
        print_status "Cleaned Temp directory"
    fi

    # Delete downloads directory contents
    if [ -d "$DATA_DIR/Downloads" ]; then
        rm -rf "$DATA_DIR/Downloads"/*
        print_status "Cleaned Downloads directory"
    fi

    # Delete logs
    if [ -d "$DATA_DIR/Logs" ]; then
        rm -rf "$DATA_DIR/Logs"/*
        print_status "Cleaned Logs directory"
    fi

    # Reset appsettings.json JWT key
    if [ -f "$DATA_DIR/appsettings.json" ]; then
        # Check if JWT key has been modified (not the default placeholder)
        if ! grep -q "\[KEY USED TO SIGN/VERIFY JWT TOKENS" "$DATA_DIR/appsettings.json"; then
            print_warning "JWT key was modified - you may want to reset appsettings.json manually"
        fi
    fi

    print_status "Full purge complete"
    echo ""
fi

# Reset database only if requested (and not already done by purge)
if [ "$RESET" = true ] && [ "$PURGE" = false ]; then
    if [ -f "$DATA_DIR/covenant.db" ]; then
        rm -f "$DATA_DIR/covenant.db" "$DATA_DIR/covenant.db-journal" "$DATA_DIR/covenant.db-shm" "$DATA_DIR/covenant.db-wal"
        print_status "Deleted database (covenant.db and lock files) - fresh registration required"
    else
        print_warning "No database found to delete"
    fi
    echo ""
fi

# Check for .NET SDK
print_status "Checking for .NET SDK..."
if ! command -v dotnet &> /dev/null; then
    print_error ".NET SDK is not installed!"
    echo ""
    echo "Install .NET 8 SDK:"
    echo "  wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh"
    echo "  chmod +x dotnet-install.sh"
    echo "  ./dotnet-install.sh --channel 8.0"
    exit 1
fi

DOTNET_VERSION=$(dotnet --version)
print_status "Found .NET SDK: $DOTNET_VERSION"

# Check for .NET 8
if [[ ! "$DOTNET_VERSION" =~ ^8\. ]]; then
    print_warning "This project requires .NET 8.0. You have $DOTNET_VERSION"
    print_warning "Build may fail. Consider installing .NET 8 SDK."
fi

# Initialize git submodules
print_status "Initializing git submodules..."
if [ -d "$SCRIPT_DIR/.git" ]; then
    git -C "$SCRIPT_DIR" submodule update --init --recursive
    print_status "Submodules initialized"
else
    print_warning "Not a git repository, skipping submodule initialization"
fi

# Check for required submodules
SHARPSPLOIT_DIR="$PROJECT_DIR/Data/ReferenceSourceLibraries/SharpSploit"
RUBEUS_DIR="$PROJECT_DIR/Data/ReferenceSourceLibraries/Rubeus"

if [ ! -f "$SHARPSPLOIT_DIR/SharpSploit.sln" ]; then
    print_error "SharpSploit submodule not found!"
    print_error "Run: git submodule update --init --recursive"
    exit 1
fi

if [ ! -f "$RUBEUS_DIR/Rubeus.sln" ]; then
    print_error "Rubeus submodule not found!"
    print_error "Run: git submodule update --init --recursive"
    exit 1
fi

print_status "Required submodules found"

# Clean if requested
if [ "$CLEAN" = true ]; then
    print_status "Cleaning project..."
    dotnet clean "$SOLUTION_FILE" -c "$CONFIG" --nologo -v q
    print_status "Clean complete"
fi

# Restore packages
print_status "Restoring NuGet packages..."
dotnet restore "$SOLUTION_FILE" --nologo -v q
print_status "Packages restored"

# Build or Publish
if [ "$PUBLISH" = true ]; then
    print_status "Publishing project ($CONFIG)..."
    dotnet publish "$PROJECT_DIR/Covenant.csproj" -c "$CONFIG" -o "$OUTPUT_DIR" --nologo
    print_status "Published to: $OUTPUT_DIR"
    echo ""
    echo "To run Covenant:"
    echo "  cd $OUTPUT_DIR && dotnet Covenant.dll"
else
    print_status "Building project ($CONFIG)..."
    dotnet build "$SOLUTION_FILE" -c "$CONFIG" --nologo
    print_status "Build complete"
fi

# Run if requested
if [ "$RUN" = true ]; then
    echo ""
    print_status "Starting Covenant..."
    echo "================================"
    if [ "$PUBLISH" = true ]; then
        cd "$OUTPUT_DIR"
        dotnet Covenant.dll
    else
        dotnet run --project "$PROJECT_DIR/Covenant.csproj" -c "$CONFIG" --no-build
    fi
fi

echo ""
print_status "Done!"
