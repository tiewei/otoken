package types

import (
	"fmt"

	"github.com/pkg/browser"
)

// URLOpener is the function opens URL for user
type URLOpener func(url string)

// BrowserOpener opens URL by opening browser
var BrowserOpener URLOpener = func(url string) {
	//nolint:errcheck
	browser.OpenURL(url)
}

// PromptOpener opens URL by prompt message to user
func PromptOpener(propter Prompter) URLOpener {
	return func(url string) {
		propter(fmt.Sprintf("Please open URL: %s", url), false)
	}
}
