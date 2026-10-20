package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

func (c *Client) sessionSID() (string, error) {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.SID, c.sessionErr
}

func (c *Client) setSessionSID(sid string, err error) {
	c.sessionMu.Lock()
	c.SID, c.sessionErr = sid, err
	c.sessionMu.Unlock()
}

func (c *Client) startSessionRefresh(refresh func(context.Context) (auth.LoginResult, error), data auth.ClientAuthData, save func([]byte) error, interval time.Duration) {
	c.refreshDone = make(chan struct{})
	c.startWorker(func() {
		defer close(c.refreshDone)
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-c.lifecycleCtx.Done():
				return
			case <-timer.C:
			}
			snapshot, err := refresh(c.lifecycleCtx)
			if c.lifecycleCtx.Err() != nil {
				return
			}
			if errors.Is(err, auth.ErrSessionInvalid) {
				c.fail(err)
				return
			}
			if err != nil {
				if c.diagnostic != nil {
					c.diagnostic("keepalive_retry")
				}
				timer.Reset(min(interval, time.Minute))
				continue
			}
			c.setSessionSID(snapshot.SID, nil)

			data.Cookies = snapshot.Cookies
			if save != nil {
				encoded, err := json.Marshal(data)
				if err == nil {
					err = save(encoded)
				}
				if err != nil && c.diagnostic != nil {
					c.diagnostic("persistence_failed")
				}
			}
			timer.Reset(interval)
		}
	})
}

// Errors reports the first terminal failure. Close cancels and joins the workers.
func (c *Client) Errors() <-chan error { return c.failures }

func (c *Client) fail(err error) {
	c.failureOnce.Do(func() {
		c.setSessionSID("", err)
		c.failures <- err
		c.lifecycleCancel()
	})
}

func (c *Client) startWorker(work func()) {
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		defer func() {
			if recover() != nil {
				c.fail(errors.New("aTrust worker panicked"))
			}
		}()
		work()
	}()
}
