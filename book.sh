#!/usr/bin/env bash
# Build or preview the mdBook site. Usage: ./book.sh [build|serve]
# The book sources live in book/ inside this checkout; run the script from
# anywhere and it resolves the checkout itself.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
book="$root/book"
if [ ! -f "$book/book.toml" ]; then
    echo "No book.toml at $book — this checkout does not carry the book." >&2
    exit 1
fi

cmd="${1:-build}"
case "$cmd" in
    build) exec mdbook build "$book" ;;
    serve) exec mdbook serve "$book" --port 3077 ;;
    *)
        echo "usage: $0 [build|serve]" >&2
        exit 2
        ;;
esac
