//go:build !unix

package audit

func discoverLockfilesUnix(root string) ([]string, error) {
	return discoverLockfilesWalk(root, nil)
}
