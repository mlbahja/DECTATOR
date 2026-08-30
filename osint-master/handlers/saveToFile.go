package handlers

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jung-kurt/gofpdf"
)

func SaveToFile(filename, data string) {
	dir := filepath.Dir(filename)

	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}
	}

	err := os.WriteFile(filename, []byte(data), 0o644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Println("Data saved in", filename)
}

func SaveAsPdf(file, content string) {
	//pdf := fpdf.new("p")
	dir := filepath.Dir(file)
	if dir != "." {
		if err := os.Mkdir(dir, 0o755); err != nil {
			fmt.Println("Error creating directory", err)
			return

		}
	}
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "", 12)

	pdf.MultiCell(190, 6, content, "", "", false)

	// 5. Build and close the final PDF output file to disk
	err := pdf.OutputFileAndClose(file)
	if err != nil {
		fmt.Println("Error saving PDF file:", err)
		return
	}

	fmt.Println("PDF data successfully saved in", file)
}
