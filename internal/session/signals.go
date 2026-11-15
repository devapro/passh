package session

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Signals are the signals that lock the TUI (§5.2): SIGHUP (e.g. the SSH
// connection dropped), SIGTERM and SIGINT.
func Signals() []os.Signal {
	return []os.Signal{syscall.SIGHUP, syscall.SIGTERM, os.Interrupt}
}

// Notify calls fn on its own goroutine for every signal of Signals until
// stop is called. While it is active, those signals don't kill the process:
// fn decides (the TUI locks, then exits). stop restores their default
// behaviour and waits until no fn call runs; it is idempotent.
func Notify(fn func(os.Signal)) (stop func()) {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, Signals()...)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			case sig := <-ch:
				fn(sig)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
			<-finished
		})
	}
}
