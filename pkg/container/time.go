package container

import "time"

func FormatFindingDate(date time.Time) string {
	return date.UTC().Format("02 Jan 2006 15:04")
}
