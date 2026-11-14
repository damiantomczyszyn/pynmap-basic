"""
Testy algorytmów timingowych przepisanych z nmap/timing.cc.

Najważniejsze: estymator RTT (Jacobson/Karels) musi dawać dokładnie te same
liczby co kod C, dlatego porównujemy z wartościami wyliczonymi ręcznie
według wzorów z adjust_timeouts2().
"""

from pynmap.timing import (
    TIMING_TEMPLATES,
    ScanPerformanceVars,
    TimeoutInfo,
    UltraTimingVals,
)

# ---------------------------------------------------------------------------
# TimeoutInfo / adjust_timeouts2
# ---------------------------------------------------------------------------


def test_initial_state_matches_template():
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    assert to.srtt == -1 and to.rttvar == -1
    assert to.timeout == 1_000_000      # INITIAL_RTT_TIMEOUT = 1000 ms
    assert to.min_timeout == 100_000    # MIN_RTT_TIMEOUT = 100 ms
    assert to.max_timeout == 10_000_000  # MAX_RTT_TIMEOUT = 10 s


def test_first_sample_formula():
    """
    Pierwsza próbka w nmapie:
        srtt    = delta
        rttvar  = box(5000, 2000000, srtt)
        timeout = srtt + (rttvar << 2)
    """
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(200_000)  # 200 ms

    assert to.srtt == 200_000
    assert to.rttvar == 200_000
    assert to.timeout == 200_000 + (200_000 << 2)  # = 1 000 000


def test_first_sample_rttvar_lower_bound():
    """Bardzo szybka odpowiedź: rttvar jest podniesiony do 5000 µs."""
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(1_000)  # 1 ms

    assert to.srtt == 1_000
    assert to.rttvar == 5_000
    # timeout = 1000 + 20000 = 21000, ale min_timeout = 100 ms wygrywa
    assert to.timeout == 100_000


def test_subsequent_sample_formula():
    """
    Kolejne próbki:
        rttdelta = delta - srtt
        srtt    += rttdelta >> 3
        rttvar  += (abs(rttdelta) - rttvar) >> 2
        timeout  = srtt + (rttvar << 2)
    """
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(200_000)
    assert (to.srtt, to.rttvar) == (200_000, 200_000)

    to.adjust(240_000)
    rttdelta = 240_000 - 200_000            # 40 000
    expected_srtt = 200_000 + (rttdelta >> 3)   # 205 000
    expected_rttvar = 200_000 + ((abs(rttdelta) - 200_000) >> 2)  # 160 000

    assert to.srtt == expected_srtt
    assert to.rttvar == expected_rttvar
    assert to.timeout == expected_srtt + (expected_rttvar << 2)


def test_timeout_is_clamped_to_max():
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(7_000_000)  # 7 s — ogromny RTT
    assert to.timeout == to.max_timeout


def test_absurd_sample_is_ignored():
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(100_000)
    before = (to.srtt, to.rttvar, to.timeout)

    to.adjust(9_000_000)  # >= 8 s, nmap odrzuca taką próbkę
    assert (to.srtt, to.rttvar, to.timeout) == before


def test_small_negative_delta_is_fixed_up():
    """nmap zamienia małą ujemną deltę na 10 ms (rozjazd zegarów)."""
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(-1_000)
    assert to.srtt == 10_000


def test_large_negative_delta_is_dropped():
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[3])
    to.adjust(-5_000_000)
    assert to.srtt == -1  # nic się nie nauczyliśmy


def test_aggressive_template_has_tighter_bounds():
    to = TimeoutInfo.from_template(TIMING_TEMPLATES[4])
    assert to.timeout == 500_000          # -T4 initial 500 ms
    assert to.max_timeout == 1_250_000    # -T4 max 1250 ms
    to.adjust(5_000_000)
    assert to.timeout == 1_250_000


# ---------------------------------------------------------------------------
# Szablony timingowe
# ---------------------------------------------------------------------------


def test_template_values_match_nmap():
    assert TIMING_TEMPLATES[0].scan_delay_ms == 300_000
    assert TIMING_TEMPLATES[1].scan_delay_ms == 15_000
    assert TIMING_TEMPLATES[2].scan_delay_ms == 400
    assert TIMING_TEMPLATES[2].max_parallelism == 1
    assert TIMING_TEMPLATES[3].max_retries == 10
    assert TIMING_TEMPLATES[4].max_retries == 6
    assert TIMING_TEMPLATES[5].max_retries == 2
    assert TIMING_TEMPLATES[5].host_timeout_ms == 900_000


def test_serial_templates_force_parallelism_one():
    for level in (0, 1, 2):
        assert TIMING_TEMPLATES[level].max_parallelism == 1


# ---------------------------------------------------------------------------
# ScanPerformanceVars
# ---------------------------------------------------------------------------


def test_perf_defaults_match_nmap():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    assert perf.low_cwnd == 1
    assert perf.max_cwnd == 300
    assert perf.group_initial_cwnd == 10
    assert perf.initial_ssthresh == 75
    assert perf.slow_incr == 1
    assert perf.ca_incr == 1
    assert perf.cc_scale_max == 50
    assert perf.group_drop_cwnd_divisor == 2.0


def test_perf_ca_incr_grows_with_timing():
    assert ScanPerformanceVars.from_template(TIMING_TEMPLATES[3]).ca_incr == 1
    assert ScanPerformanceVars.from_template(TIMING_TEMPLATES[4]).ca_incr == 2
    assert ScanPerformanceVars.from_template(TIMING_TEMPLATES[5]).ca_incr == 2


def test_perf_ssthresh_divisor_by_level():
    assert ScanPerformanceVars.from_template(
        TIMING_TEMPLATES[3]
    ).host_drop_ssthresh_divisor == 1.5
    assert ScanPerformanceVars.from_template(
        TIMING_TEMPLATES[4]
    ).host_drop_ssthresh_divisor == 4.0 / 3.0
    assert ScanPerformanceVars.from_template(
        TIMING_TEMPLATES[5]
    ).host_drop_ssthresh_divisor == 1.25


def test_parallelism_limits_are_respected():
    perf = ScanPerformanceVars.from_template(
        TIMING_TEMPLATES[3], min_parallelism=5, max_parallelism=20
    )
    assert perf.low_cwnd == 5
    assert perf.max_cwnd == 20
    assert 5 <= perf.group_initial_cwnd <= 20


# ---------------------------------------------------------------------------
# UltraTimingVals (AIMD)
# ---------------------------------------------------------------------------


def test_slow_start_growth():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    assert t.cwnd == 10.0 and t.ssthresh == 75

    t.num_replies_expected = 1
    t.ack(perf)
    # slow start: cwnd += slow_incr * cc_scale (=1.0 przy 1 oczekiwanej/1 otrzymanej)
    assert t.cwnd == 11.0


def test_slow_start_does_not_overshoot_ssthresh():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    t.cwnd = 74.5
    t.num_replies_expected = 1
    t.ack(perf)
    assert t.cwnd == float(t.ssthresh)


def test_congestion_avoidance_growth_is_slower():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    t.cwnd = 100.0
    t.ssthresh = 75
    t.num_replies_expected = 1
    t.ack(perf)
    # congestion avoidance: cwnd += ca_incr / cwnd
    assert t.cwnd == 100.0 + 1 / 100.0


def test_cwnd_capped_at_max():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    t.cwnd = float(perf.max_cwnd)
    t.ssthresh = 10
    t.num_replies_expected = 1
    t.ack(perf)
    assert t.cwnd == float(perf.max_cwnd)


def test_host_drop_collapses_window():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    t.cwnd = 50.0
    t.drop(in_flight=30, perf=perf, now=1.0)

    assert t.cwnd == float(perf.low_cwnd)          # do 1, jak po RTO w TCP
    assert t.ssthresh == int(30 / 1.5)             # = 20
    assert t.last_drop == 1.0


def test_group_drop_is_gentler():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=True, now=0.0)
    t.cwnd = 50.0
    t.drop_group(in_flight=30, perf=perf, now=2.0)

    assert t.cwnd == 25.0                           # podział przez 2, nie do 1
    assert t.ssthresh == int(30 / 1.5)


def test_cc_scale_is_capped():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    t.num_replies_expected = 10_000
    t.num_replies_received = 1
    assert t.cc_scale(perf) == float(perf.cc_scale_max)


def test_cc_scale_without_replies_is_neutral():
    perf = ScanPerformanceVars.from_template(TIMING_TEMPLATES[3])
    t = UltraTimingVals.init_for(perf, group=False, now=0.0)
    assert t.cc_scale(perf) == 1.0
