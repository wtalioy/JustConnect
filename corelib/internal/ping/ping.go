package ping

import "time"

type Target struct {
	Host     string
	Port     int
	Counter  int
	Interval time.Duration
	Timeout  time.Duration
}

type Result struct {
	Err            error
	Counter        int
	SuccessCounter int
	Target         *Target
	MinDuration    time.Duration
	MaxDuration    time.Duration
	TotalDuration  time.Duration
}

func (result Result) Avg() time.Duration {
	if result.SuccessCounter == 0 {
		return 0
	}
	return result.TotalDuration / time.Duration(result.SuccessCounter)
}
func (result Result) Failed() int { return result.Counter - result.SuccessCounter }
