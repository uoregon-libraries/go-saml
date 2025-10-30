package main

import (
	"fmt"
	"log/slog"
	"os"
)

// legacyLog is a slog.Logger that tries to implement the awful legacy-style
// samlidp logging interface. SAMLIDP DOESN'T EVEN USE MOST OF THESE METHODS!
type legacyLog struct {
	slog *slog.Logger
}

func (l legacyLog) Print(v ...interface{}) {
	var msg = fmt.Sprint(v...)
	if len(msg) > 7 && msg[:7] == "ERROR: " {
		l.slog.Error(msg[7:])
		return
	}
	l.slog.Info(msg)
}

func (l legacyLog) Println(v ...interface{}) {
	l.Print(v...)
}

func (l legacyLog) Printf(format string, v ...interface{}) {
	l.Print(fmt.Sprintf(format, v...))
}

func (l legacyLog) Fatal(v ...interface{}) {
	l.slog.Error(fmt.Sprint(v...))
	os.Exit(1)
}

func (l legacyLog) Fatalln(v ...interface{}) {
	l.Fatal(v...)
}

func (l legacyLog) Fatalf(format string, v ...interface{}) {
	l.Fatal(fmt.Sprintf(format, v...))
}

func (l legacyLog) Panic(v ...interface{}) {
	l.Fatal(v...)
}

func (l legacyLog) Panicln(v ...interface{}) {
	l.Fatal(v...)
}

func (l legacyLog) Panicf(format string, v ...interface{}) {
	l.Fatalf(format, v...)
}
