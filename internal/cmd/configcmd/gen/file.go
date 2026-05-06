package gen

import (
	"os"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644) // #nosec G306
}
