// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package candles

import (
	"testing"
	"time"
)

const fiveMins = 5 * 60 * 1000

func TestCache(t *testing.T) {
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()
	const binSize = 10
	const cacheCapacity = 5
	cache := NewCache(cacheCapacity, binSize)

	if cache.BinSize != binSize {
		t.Fatalf("wrong bin size. wanted %d, got %d", binSize, cache.BinSize)
	}

	makeCandle := func(startStamp, endStamp, matchVol, quoteVol, bookVol, startRate, endRate, lowRate, highRate uint64) *Candle {
		return &Candle{
			MatchVolume: matchVol,
			QuoteVolume: quoteVol,
			StartStamp:  startStamp,
			EndStamp:    endStamp,
			StartRate:   startRate,
			EndRate:     endRate,
			HighRate:    highRate,
			LowRate:     lowRate,
		}
	}

	checkCandleStamps := func(candle *Candle, startStamp, endStamp uint64) {
		t.Helper()
		if candle.StartStamp != startStamp {
			t.Fatalf("wrong StartStamp. wanted %d, got %d", startStamp, candle.StartStamp)
		}
		if candle.EndStamp != endStamp {
			t.Fatalf("wrong EndStamp. wanted %d, got %d", endStamp, candle.EndStamp)
		}
	}

	checkCandleVolumes := func(candle *Candle, matchVol, quoteVol, bookVol uint64) {
		t.Helper()
		if candle.MatchVolume != matchVol {
			t.Fatalf("wrong MatchVolume. wanted %d, got %d", matchVol, candle.MatchVolume)
		}
		if candle.QuoteVolume != quoteVol {
			t.Fatalf("wrong QuoteVolume. wanted %d, got %d", quoteVol, candle.QuoteVolume)
		}
	}

	checkCandleRates := func(candle *Candle, startRate, endRate, lowRate, highRate uint64) {
		t.Helper()
		if candle.StartRate != startRate {
			t.Fatalf("wrong StartRate. wanted %d, got %d", startRate, candle.StartRate)
		}
		if candle.EndRate != endRate {
			t.Fatalf("wrong EndRate. wanted %d, got %d", endRate, candle.EndRate)
		}
		if candle.LowRate != lowRate {
			t.Fatalf("wrong LowRate. wanted %d, got %d", lowRate, candle.LowRate)
		}
		if candle.HighRate != highRate {
			t.Fatalf("wrong HighRate. wanted %d, got %d", highRate, candle.HighRate)
		}
	}

	// Check basic functionality.
	cache.Add(makeCandle(11, 12, 100, 101, 100, 100, 100, 50, 150)) // start rate 100
	if len(cache.Candles) != 1 {
		t.Fatalf("Add didn't add")
	}
	lastCandle := cache.Last()
	if lastCandle == nil {
		t.Fatalf("failed to retrieve last candle")
	}
	checkCandleStamps(lastCandle, 11, 12)
	checkCandleVolumes(lastCandle, 100, 101, 100)
	checkCandleRates(lastCandle, 100, 100, 50, 150)

	// A bunch of stamps from the same bin should not add any candles.
	cache.Add(makeCandle(12, 13, 100, 101, 100, 100, 100, 25, 100)) // low rate 25
	cache.Add(makeCandle(13, 14, 100, 101, 100, 100, 100, 50, 200)) // high rate 200
	cache.Add(makeCandle(14, 15, 100, 101, 150, 100, 125, 50, 100)) // end book volume 150, end rate 125
	if len(cache.Candles) != 1 {
		t.Fatalf("Add didn't add")
	}
	checkCandleStamps(cache.Last(), 11, 15)
	checkCandleVolumes(cache.Last(), 400, 404, 150)
	checkCandleRates(cache.Last(), 100, 125, 25, 200)

	// Two candles each in a new bin.
	cache.Add(makeCandle(25, 27, 10, 11, 12, 13, 14, 15, 16))
	cache.Add(makeCandle(41, 48, 17, 18, 19, 20, 21, 22, 23))
	if len(cache.Candles) != 3 {
		t.Fatalf("New candles didn't add")
	}
	checkCandleStamps(cache.Last(), 41, 48)
	checkCandleVolumes(cache.Last(), 17, 18, 19)
	checkCandleRates(cache.Last(), 20, 21, 22, 23)

	// Candle combination is based on end stamp only.
	cache.Add(makeCandle(49, 51, 24, 25, 26, 27, 28, 29, 30))
	if len(cache.Candles) != 4 {
		t.Fatalf("straddling candle didn't create new entry")
	}

	// Adding two more should only increase length by 1, since capacity is 5.
	cache.Add(makeCandle(61, 69, 24, 25, 26, 27, 28, 29, 30))
	cache.Add(makeCandle(71, 79, 54321, 25, 26, 27, 28, 29, 30))
	if len(cache.Candles) != cacheCapacity {
		t.Fatalf("cache size not at capacity. wanted %d, found %d", cacheCapacity, len(cache.Candles))
	}
	// The cache becomes circular, so the most recent will be at the previously
	// oldest index, 0.
	if cache.Last() != &cache.Candles[0] {
		t.Fatalf("cache didn't wrap")
	}

	// Encoding should still put the most recent last.
	wc := cache.WireCandles(5)
	if len(wc.MatchVolumes) != 5 {
		t.Fatalf("encoded %d wire candles, expected 5", len(wc.MatchVolumes))
	}
	if wc.MatchVolumes[4] != 54321 {
		t.Fatalf("encoding order incorrect")
	}

	// Same thing even if we request fewer.
	wc = cache.WireCandles(1)
	if wc.MatchVolumes[0] != 54321 {
		t.Fatalf("single candle wasn't the last")
	}
}

func TestDelta(t *testing.T) {
	tNow := time.Now().Truncate(time.Millisecond)
	now := uint64(tNow.UnixMilli())
	aDayAgo := now - 86400*1000

	c := NewCache(5, fiveMins)
	// This one shouldn't be included.
	c.Add(&Candle{
		MatchVolume: 100,
		StartStamp:  aDayAgo - fiveMins,
		EndStamp:    aDayAgo,
		StartRate:   100,
		EndRate:     100,
	})
	c.Add(&Candle{
		MatchVolume: 150,
		StartStamp:  aDayAgo,
		EndStamp:    aDayAgo + fiveMins,
		StartRate:   100,
		EndRate:     150,
	})
	c.Add(&Candle{
		MatchVolume: 50,
		StartStamp:  now - fiveMins,
		EndStamp:    now,
		StartRate:   125,
		EndRate:     175,
	})

	startCandle := &c.Candles[1]

	testTime := tNow
	check24 := func(expDelta float64, expVol uint64) {
		t.Helper()
		high, low := (expDelta + 0.01), (expDelta - 0.01)
		delta24, vol24, _, _ := c.Delta(testTime.Add(-time.Hour * 24))
		if delta24 < low || delta24 > high {
			t.Fatalf("wrong delta24. expected %.3f, got, %.3f", expDelta, delta24)
		}
		if vol24 != expVol {
			t.Fatalf("wrong 24-hour volume. wanted %d, got %d", expVol, vol24)
		}
	}

	// Basic function test.
	check24(0.75, 200)

	// Test halfway through the candle time. 125 -> 175 = +0.4, vol = 75 + 50
	testTime = tNow.Add(time.Minute * 5 / 2)
	check24(0.4, 125)

	// Larger start rate tests underflow handling.
	startCandle.StartRate, startCandle.EndRate = startCandle.EndRate, startCandle.StartRate
	check24(0.4, 125)
	startCandle.StartRate, startCandle.EndRate = startCandle.EndRate, startCandle.StartRate

	testTime = tNow

	// Zero-handling tests.

	// A zero start rate on the first (used) candle should result in the EndRate
	// being used as the base point instead. 125 -> 175 = 40% increase
	startCandle.StartRate = 0
	startCandle.EndRate = 125
	check24(0.40, 200)

	// A zero on the end rate too should result in that stick being skipped, but
	// same result since start rate of next candle is same as end rate of this
	// candle.
	startCandle.EndRate = 0
	check24(0.40, 200)

	// Set that EndRate again, but delete the last candles EndRate, forcing use
	// of the start rate instead. 100 -> 125 = 25% increase
	startCandle.EndRate = 100
	c.Candles[2].EndRate = 0
	check24(0.25, 200)

}

func TestDeltaPartialDays(t *testing.T) {
	tNow := time.Now().Truncate(time.Millisecond)
	now := uint64(tNow.UnixMilli())
	aDayAgo := now - 86400*1000

	c := NewCache(5, fiveMins)
	c.Add(&Candle{
		MatchVolume: 444,
		StartStamp:  aDayAgo,
		EndStamp:    now,
		StartRate:   50,
		EndRate:     150,
	})
	delta6, vol6, _, _ := c.Delta(tNow.Add(-time.Hour * 6))
	// In the last 6 hours, the rate would be interpreted as going from 125 to
	// 150, change = 25/125 = 0.20
	// Note that the cache would never be used with duration < binSize this way
	// in practice.
	if delta6 < 0.19 || delta6 > 0.21 {
		t.Fatalf("wrong delta6. expected 0.25, got, %.3f", delta6)
	}
	if vol6 < 110 || vol6 > 111 {
		t.Fatalf("wrong 12-hour volume. wanted 110, got %d", vol6)
	}
}

func TestCandlesCopy(t *testing.T) {
	smallCap := 10
	binSize := uint64(60 * 5 * 1000)
	cacheWithCandles := func(adds uint64) *Cache {
		cache := NewCache(smallCap, binSize)
		for i := uint64(0); i < adds; i++ {
			candle := &Candle{
				StartStamp: i * binSize,
				EndStamp:   (i + 1) * binSize,
			}
			cache.Add(candle)
		}
		return cache
	}
	tests := []struct {
		name                string
		adds                uint64
		wantLen             int
		wantFirst, wantLast uint64 // EndStamp times
	}{{
		name: "no candles",
	}, {
		name:      "one candle",
		adds:      1,
		wantLen:   1,
		wantFirst: binSize,
		wantLast:  binSize,
	}, {
		name:      "five candles",
		adds:      5,
		wantLen:   5,
		wantFirst: binSize,
		wantLast:  binSize * 5,
	}, {
		name:      "at cap before reusing zero",
		adds:      uint64(smallCap),
		wantLen:   smallCap,
		wantFirst: binSize,
		wantLast:  binSize * 10,
	}, {
		name:      "first candle over cap",
		adds:      11,
		wantLen:   smallCap,
		wantFirst: binSize * (11 + 1 - uint64(smallCap)),
		wantLast:  binSize * 11,
	}, {
		name:      "many times over cap",
		adds:      1345,
		wantLen:   smallCap,
		wantFirst: binSize * (1345 + 1 - uint64(smallCap)),
		wantLast:  binSize * 1345,
	}}
	for _, test := range tests {
		c := cacheWithCandles(test.adds)
		cc := c.CandlesCopy()
		if len(cc) != test.wantLen {
			t.Fatalf("%q: wanted len %d but got %d", test.name, test.wantLen, len(cc))
		}
		if test.wantLen != 0 {
			first := cc[0].EndStamp
			if first != test.wantFirst {
				t.Fatalf("%q: wanted first end stamp %d but got %d", test.name, test.wantFirst, first)
			}
			last := cc[len(cc)-1].EndStamp
			if last != test.wantLast {
				t.Fatalf("%q: wanted last end stamp %d but got %d", test.name, test.wantLast, last)
			}
		}
	}
}
