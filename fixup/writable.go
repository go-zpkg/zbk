package fixup

import "io/fs"

// ensureWritable adds the owner write bit when a file lacks it, and returns a
// function restoring the original mode.
//
// Every relocation this package performs is an IN-PLACE rewrite, and a package
// is entitled to install its files read-only — autotools does it routinely, and
// tcl-lang.org does it to every library it ships:
//
//	-r-xr-xr-x  lib/libtcl8.6.dylib
//
// os.WriteFile and os.OpenFile(O_RDWR) both reopen an existing file with its
// existing mode, so the write fails with EACCES and the whole build dies at the
// last step, having compiled and installed correctly:
//
//	build failed: fix-up: open …/lib/libtcl8.6.dylib: permission denied
//
// Restoring the mode matters as much as lifting it: the artifact must ship the
// permissions the package chose, not the ones we needed for a moment.
func ensureWritable(path string) (func(), error) {
	fi, err := osStat(path)
	if err != nil {
		return nil, err
	}
	mode := fi.Mode().Perm()
	if mode&0o200 != 0 {
		return func() {}, nil
	}
	if err := osChmod(path, mode|0o200); err != nil {
		return nil, err
	}
	return func() { _ = osChmod(path, mode) }, nil
}

// modeOf is ensureWritable's companion for callers that also need the original
// mode to hand to os.WriteFile.
func modeOf(path string) (fs.FileMode, error) {
	fi, err := osStat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode().Perm(), nil
}
