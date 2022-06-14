package types

import (
	"bufio"
	"fmt"
	"os"
)

// Prompter provides a way to prompt user information
type Prompter func(msg string, needConfirm bool)

// StdoutPrompter uses stdin and stdout to prompt user information
var StdoutPrompter = func(msg string, needConfirm bool) {
	fmt.Fprintln(os.Stdout, msg)
	if needConfirm {
		fmt.Fprintln(os.Stdout, "Press [Enter] to confirm")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		//nolint:errcheck
		scanner.Err()
	}
}
