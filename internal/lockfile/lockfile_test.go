package lockfile

import "testing"

func TestMavenLockfiles(t *testing.T) {
	for _, name := range []string{"pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile"} {
		if !IsRootName(name) {
			t.Fatalf("%q should be a root lockfile", name)
		}
		if got := Ecosystem(name); got != "Maven" {
			t.Fatalf("Ecosystem(%q) = %q, want Maven", name, got)
		}
	}
}
