package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	outputFile := flag.String("o", "tlv_types_generated.go", "Output file for generated code")
	flag.Parse()

	f, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fmt.Fprintf(f, "package tlv\n\n")
	fmt.Fprintf(f, "import \"fmt\"\n\n")

	// Define the new interface type constraint
	fmt.Fprintf(f, "type TlvTypes interface {\n")

	// Generate type constraints for each TlvType
	for i := 0; i <= 99; i++ {
		switch {
		case i == 0:
			fmt.Fprintf(f, "\tTlvType%d | ", i)
		case i < 99:
			fmt.Fprintf(f, "TlvType%d | ", i)
		default:
			fmt.Fprintf(f, "TlvType%d", i)
		}
	}

	fmt.Fprintf(f, "\n}\n\n")

	fmt.Fprintf(f, "func TlvTypeStruct(typeVal Type) TlvType {\n")
	fmt.Fprintf(f, "\tswitch typeVal {\n")
	for i := 0; i <= 99; i++ {
		fmt.Fprintf(f, "\tcase %d:\n", i)
		fmt.Fprintf(f, "\t\treturn &TlvType%d{}\n", i)
	}
	fmt.Fprintf(f, "\tdefault:\n")
	fmt.Fprintf(f, "\t\treturn nil\n")
	fmt.Fprintf(f, "\t}\n")
	fmt.Fprintf(f, "}\n\n")

	fmt.Fprintf(f, "func GetTypeVal[T TlvTypes](t T) Type {\n")
	fmt.Fprintf(f, "\tswitch any(t).(type) {\n")
	for i := 0; i <= 99; i++ {
		fmt.Fprintf(f, "\tcase TlvType%d:\n", i)
		fmt.Fprintf(f, "\t\treturn %d\n", i)
	}
	fmt.Fprintf(f, "\tdefault:\n")
	fmt.Fprintf(f, "\t\tpanic(fmt.Sprintf(\"unknown type %%T\", t))\n")
	fmt.Fprintf(f, "\t}\n")
	fmt.Fprintf(f, "}\n\n")

	for i := 0; i <= 99; i++ {
		fmt.Fprintf(f, "type TlvType%d struct {}\n\n", i)
		fmt.Fprintf(f, "func (t *TlvType%d) typeVal() Type {\n", i)
		fmt.Fprintf(f, "\treturn %d\n", i)
		fmt.Fprintf(f, "}\n\n")
	}
}
