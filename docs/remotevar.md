

A VSCP unit is describing it's configuration to the world with a
register model where each register is eight bit in width. This is often
inconvenient for a human user who is used to higher level types and this
is what *abstractions* are there for. They sit above registers and
specify types as strings, floats, integers and other such higher level
types.

## Counters

Real time counter values that will increase or decrease over time,
depending on settings in the counters control register, if a pulse is
available on the channel.

| Name     | Type      | Description           |
| -------- | --------- | --------------------- |
| counter0 | uint32\_t | Counter for channel 0 |
| counter1 | uint32\_t | Counter for channel 1 |
| counter2 | uint32\_t | Counter for channel 2 |
| counter3 | uint32\_t | Counter for channel 3 |

## Frequency

Frequency for the signal on the channel.

| Name       | Type      | Description             |
| ---------- | --------- | ----------------------- |
| frequency0 | uint32\_t | Frequency for channel 0 |
| frequency1 | uint32\_t | Frequency for channel 1 |
| frequency2 | uint32\_t | Frequency for channel 2 |
| frequency3 | uint32\_t | Frequency for channel 3 |

## k constants for linearization

Linearization is available so a measurement y can be calculated from

    y = k*x + m

where x is either the current counter value for a channel or the current
frequency for a channel.

| Name   | Type  | Description                                                                                |
| ------ | ----- | ------------------------------------------------------------------------------------------ |
| ch0\_k | float | A 32-bit floating point k-constant for linearization of channel 0 counter/frequency value. |
| ch1\_k | float | A 32-bit floating point k-constant for linearization of channel 1 counter/frequency value. |
| ch2\_k | float | A 32-bit floating point k-constant for linearization of channel 2 counter/frequency value. |
| ch3\_k | float | A 32-bit floating point k-constant for linearization of channel 3 counter/frequency value. |

## m constants for linearization

Linearization is available so a measurement y can be calculated from

    y = k*x + m

where x is either the current counter value for a channel or the current
frequency for a channel.

| Name    | Type  | Description                                                                                |
| ------- | ----- | ------------------------------------------------------------------------------------------ |
| ch0\_m0 | float | A 32-bit floating point m-constant for linearization of channel 0 counter/frequency value. |
| ch1\_m1 | float | A 32-bit floating point m-constant for linearization of channel 1 counter/frequency value. |
| ch2\_m2 | float | A 32-bit floating point m-constant for linearization of channel 2 counter/frequency value. |
| ch3\_m3 | float | A 32-bit floating point m-constant for linearization of channel 3 counter/frequency value. |

## Counter alarm levels

Counter alarm level. If the counter go above (or below) this value an
alarm will be issued (if active). The alarm will be flagged in the alarm
register and the alarm condition is rested if the counter value goes
below counter value - hysteresis.

| Name               | Type      | Description                                 |
| ------------------ | --------- | ------------------------------------------- |
| cnt0\_alarm\_level | uint32\_t | A 32-bit counter alarm level for channel 0. |
| cnt1\_alarm\_level | uint32\_t | A 32-bit counter alarm level for channel 1. |
| cnt2\_alarm\_level | uint32\_t | A 32-bit counter alarm level for channel 2. |
| cnt3\_alarm\_level | uint32\_t | A 32-bit counter alarm level for channel 3. |

## Counter hysteresis

Counter hysteresis is the value the counter should drop with before an
alarm condition is no longer active. This means that the next time the
limit is passed the alarm condition is active again.

| Name             | Type      | Description                                      |
| ---------------- | --------- | ------------------------------------------------ |
| cnt0\_hysteresis | uint16\_t | A 16-bit counter hysteresis value for channel 0. |
| cnt1\_hysteresis | uint16\_t | A 16-bit counter hysteresis value for channel 1. |
| cnt2\_hysteresis | uint16\_t | A 16-bit counter hysteresis value for channel 2. |
| cnt3\_hysteresis | uint16\_t | A 16-bit counter hysteresis value for channel 3. |

## Counter reload values

This is a value reloaded (if activated) to the counter when it counts
down to zero.

| Name         | Type      | Description                                  |
| ------------ | --------- | -------------------------------------------- |
| cnt0\_reload | uint32\_t | A 32-bit counter reload value for channel 0. |
| cnt1\_reload | uint32\_t | A 32-bit counter reload value for channel 1. |
| cnt2\_reload | uint32\_t | A 32-bit counter reload value for channel 2. |
| cnt3\_reload | uint32\_t | A 32-bit counter reload value for channel 3. |

## Frequency low alarms

Frequency low alarm level. Alarm condition is active if the frequency
goes below this value. The alarm condition is active until the frequency
go up to a value that is this value plus configured frequency
hysteresis.

| Name              | Type      | Description                               |
| ----------------- | --------- | ----------------------------------------- |
| freq0\_alarm\_low | uint16\_t | A 32-bit low alarm level for frequency 0. |
| freq1\_alarm\_low | uint16\_t | A 32-bit low alarm level for frequency 1. |
| freq2\_alarm\_low | uint16\_t | A 32-bit low alarm level for frequency 2. |
| freq3\_alarm\_low | uint16\_t | A 32-bit low alarm level for frequency 3. |

## Frequency high alarms

Frequency high alarm level. Alarm condition is active if the frequency
goes above this value. The alarm condition is active until the frequency
go down to a value that is this value minus configured frequency
hysteresis.

| Name               | Type      | Description                                |
| ------------------ | --------- | ------------------------------------------ |
| freq0\_alarm\_high | uint16\_t | A 32-bit high alarm level for frequency 0. |
| freq1\_alarm\_high | uint16\_t | A 32-bit high alarm level for frequency 1. |
| freq2\_alarm\_high | uint16\_t | A 32-bit high alarm level for frequency 2. |
| freq3\_alarm\_high | uint16\_t | A 32-bit high alarm level for frequency 3. |

## Frequency hysteresis

This is the hysteresis used for frequency high/low alarms.

| Name              | Type      | Description                                |
| ----------------- | --------- | ------------------------------------------ |
| freq0\_hysteresis | uint16\_t | A 16-bit hysteresis value for frequency 0. |
| freq1\_hysteresis | uint16\_t | A 16-bit hysteresis value for frequency 1. |
| freq2\_hysteresis | uint16\_t | A 16-bit hysteresis value for frequency 2. |
| freq3\_hysteresis | uint16\_t | A 16-bit hysteresis value for frequency 3. |

  
[filename](./bottom-copyright.md ':include')