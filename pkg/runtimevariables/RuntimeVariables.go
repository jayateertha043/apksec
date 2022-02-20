package runtimevariables

import (
	"strconv"
	"sync"
	"time"
)

type RunTimeVariables struct {
	starttime     string
	outputrootdir string
	mu            sync.RWMutex
}

var (
	runtimevar      *RunTimeVariables
	runtimevar_once sync.Once
)

func GetRunTimeVariables() *RunTimeVariables {
	runtimevar_once.Do(func() {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		runtimevar = &RunTimeVariables{
			starttime:     timestamp,
			outputrootdir: "apksec_" + timestamp,
		}
	})
	return runtimevar
}

func (r *RunTimeVariables) GetStartTimeStampString() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.starttime
}
func (r *RunTimeVariables) GetOutputRootDir() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.outputrootdir
}
