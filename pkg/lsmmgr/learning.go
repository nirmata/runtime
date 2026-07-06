package lsmmgr

import "time"

func (l *LsmManager) Start(uid string, labels map[string]string, dur time.Duration)

func (l *LsmManager) Stop(uid string)

func (l *LsmManager) Read(uid string) (map[string]int32, error)
