package migrate

import "github.com/golang/glog"

// Init forces GO to call init() on all the files in the package
func Init() {
	glog.Info("Loading all migrations...")
}
