package main

import "go.uber.org/zap/zapcore"

func main() {
	Execute()
}

func verbosityLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	if level >= zapcore.DebugLevel {
		zapcore.CapitalLevelEncoder(level, enc)
		return
	}
	enc.AppendString("DEBUG")
}
