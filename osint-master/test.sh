
#!/bin/bash

echo "=================================="
echo "      OSINT MASTER AUDIT TEST"
echo "=================================="

echo
echo "1. Building project..."
go build -o osintmaster

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

echo
echo "=================================="
echo "HELP"
echo "=================================="
./osintmaster --help

echo
read -p "Press Enter to continue..."

echo
echo "=================================="
echo "IP LOOKUP"
echo "=================================="
./osintmaster -i 8.8.8.8 -o ip.txt

echo
echo "Content of ip.txt:"
cat ip.txt

echo
read -p "Press Enter to continue..."

echo
echo "=================================="
echo "USERNAME LOOKUP"
echo "=================================="
./osintmaster -u torvalds -o user.txt

echo
echo "Content of user.txt:"
cat user.txt

echo
read -p "Press Enter to continue..."

echo
echo "=================================="
echo "DOMAIN ENUMERATION"
echo "=================================="
./osintmaster -d github.com -o domain.txt

echo
echo "Content of domain.txt:"
cat domain.txt

echo
read -p "Press Enter to continue..."

echo
echo "=================================="
echo "INVALID IP"
echo "=================================="
./osintmaster -i 999.999.999.999

echo
echo "=================================="
echo "INVALID USERNAME"
echo "=================================="
./osintmaster -u ""

echo
echo "=================================="
echo "INVALID DOMAIN"
echo "=================================="
./osintmaster -d invalid-domain

echo
echo "=================================="
echo "DONE"
echo "=================================="

