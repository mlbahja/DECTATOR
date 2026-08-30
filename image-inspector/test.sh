#!/bin/bash

echo "======================================"
echo "Image Inspector Audit Test"
echo "======================================"

echo ""
echo "[1] Testing --help"
python3 image_inspector.py --help

echo ""
echo "======================================"
echo "[2] Testing Metadata Extraction"
echo "======================================"

rm -f metadata.txt

python3 image_inspector.py -m -o metadata.txt image-example1.jpeg

echo ""
echo "Checking metadata.txt..."

if [ -f metadata.txt ]; then
    echo "[PASS] metadata.txt created."
    echo "--------------------------------------"
    cat metadata.txt
    echo "--------------------------------------"
else
    echo "[FAIL] metadata.txt was not created."
fi

echo ""
echo "======================================"
echo "[3] Testing Steganography Detection"
echo "======================================"

rm -f hidden_data.txt

python3 image_inspector.py -s -o hidden_data.txt image-example1.jpeg

echo ""

if [ -f hidden_data.txt ]; then
    echo "[PASS] hidden_data.txt created."
    echo "--------------------------------------"
    cat hidden_data.txt
    echo "--------------------------------------"
else
    echo "[INFO] hidden_data.txt was not created."
    echo "This is expected if no hidden PGP key exists."
fi

echo ""
echo "======================================"
echo "[4] Testing Combined Options"
echo "======================================"

python3 image_inspector.py -m -s -o results.txt image-example1.jpeg

echo ""

echo "Exit code: $?"

echo ""
echo "======================================"
echo "Tests Finished"
echo "======================================"