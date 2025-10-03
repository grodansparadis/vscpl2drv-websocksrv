# Registers

## Page 0

### Zone information

| Register | Page | Description                         |
| -------- | ---- | ----------------------------------- |
| 0        | 0    | The zone this module belongs to     |
| 1        | 0    | The sub zone this module belongs to |
| 2        | 0    | Sub zone for channel 0              |
| 3        | 0    | Sub zone for channel 1              |
| 4        | 0    | Sub zone for channel 2              |
| 5        | 0    | Sub zone for channel 3              |

### Control registers for counters

<table>
<thead>
<tr class="header">
<th>Register</th>
<th>Page</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>6</td>
<td>0</td>
<td>Control register for channel 0 counter<br />
<br />
<strong>Bit 0</strong> - Counting direction (0=up/1=down).<br />
<strong>Bit 1</strong> - Enable alarm level.<br />
<strong>Bit 2</strong> - Reload value on zero.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable counter.</td>
</tr>
<tr class="even">
<td>7</td>
<td>0</td>
<td>Control register for channel 1 counter<br />
<br />
<strong>Bit 0</strong> - Counting direction (0=up/1=down).<br />
<strong>Bit 1</strong> - Enable alarm level.<br />
<strong>Bit 2</strong> - Reload value on zero.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable counter.</td>
</tr>
<tr class="odd">
<td>8</td>
<td>0</td>
<td>Control register for channel 2 counter<br />
<br />
<strong>Bit 0</strong> - Counting direction (0=up/1=down).<br />
<strong>Bit 1</strong> - Enable alarm level.<br />
<strong>Bit 2</strong> - Reload value on zero.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable counter.</td>
</tr>
<tr class="even">
<td>9</td>
<td>0</td>
<td>Control register for channel 3 counter<br />
<br />
<strong>Bit 0</strong> - Counting direction (0=up/1=down).<br />
<strong>Bit 1</strong> - Enable alarm level.<br />
<strong>Bit 2</strong> - Reload value on zero.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable counter.</td>
</tr>
</tbody>
</table>

### Control registers for frequency

<table>
<thead>
<tr class="header">
<th>Register</th>
<th>Page</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>10</td>
<td>0</td>
<td>Control register for channel 0 frequency<br />
<br />
<strong>Bit 0</strong> - Enable frequency low alarm.<br />
<strong>Bit 1</strong> - Enable frequency high alarm.<br />
<strong>Bit 2</strong> - Reserved.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable frequency measurements.</td>
</tr>
<tr class="even">
<td>11</td>
<td>0</td>
<td>Control register for channel 1 frequency<br />
<br />
<strong>Bit 0</strong> - Enable frequency low alarm.<br />
<strong>Bit 1</strong> - Enable frequency high alarm.<br />
<strong>Bit 2</strong> - Reserved.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable frequency measurements.</td>
</tr>
<tr class="odd">
<td>12</td>
<td>0</td>
<td>Control register for channel 2 frequency<br />
<br />
<strong>Bit 0</strong> - Enable frequency low alarm.<br />
<strong>Bit 1</strong> - Enable frequency high alarm.<br />
<strong>Bit 2</strong> - Reserved.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable frequency measurements.</td>
</tr>
<tr class="even">
<td>13</td>
<td>0</td>
<td>Control register for channel 3 frequency<br />
<br />
<strong>Bit 0</strong> - Enable frequency low alarm.<br />
<strong>Bit 1</strong> - Enable frequency high alarm.<br />
<strong>Bit 2</strong> - Reserved.<br />
<strong>Bit 3</strong> - Reserved.<br />
<strong>Bit 4</strong> - Reserved.<br />
<strong>Bit 5</strong> - Reserved.<br />
<strong>Bit 6</strong> - Reserved.<br />
<strong>Bit 7</strong> - Enable frequency measurements.</td>
</tr>
</tbody>
</table>

### Counter reset

<table>
<thead>
<tr class="header">
<th>Register</th>
<th>Page</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>14</td>
<td>0</td>
<td>Reset channel 0 counter<br />
Reset counter 0 by writing 0x55 to this register. Will read back as zero for all values except 0x55.</td>
</tr>
<tr class="even">
<td>15</td>
<td>0</td>
<td>Reset channel 1 counter<br />
Reset counter 1 by writing 0x55 to this register. Will read back as zero for all values except 0x55.</td>
</tr>
<tr class="odd">
<td>16</td>
<td>0</td>
<td>Reset channel 2 counter<br />
Reset counter 2 by writing 0x55 to this register. Will read back as zero for all values except 0x55.</td>
</tr>
<tr class="even">
<td>17</td>
<td>0</td>
<td>Reset channel 3 counter<br />
Reset counter 3 by writing 0x55 to this register. Will read back as zero for all values except 0x55.</td>
</tr>
</tbody>
</table>

### Counters

| Register | Page | Description            |
| -------- | ---- | ---------------------- |
| 18       | 0    | 32-bit counter 0 (MSB) |
| 19       | 0    | 32-bit counter 0       |
| 20       | 0    | 32-bit counter 0       |
| 21       | 0    | 32-bit counter 0 (LSB) |
| 22       | 0    | 32-bit counter 1 (MSB) |
| 23       | 0    | 32-bit counter 1       |
| 24       | 0    | 32-bit counter 1       |
| 25       | 0    | 32-bit counter 1 (LSB) |
| 26       | 0    | 32-bit counter 2 (MSB) |
| 27       | 0    | 32-bit counter 2       |
| 28       | 0    | 32-bit counter 2       |
| 29       | 0    | 32-bit counter 2 (LSB) |
| 30       | 0    | 32-bit counter 3 (MSB) |
| 31       | 0    | 32-bit counter 3       |
| 32       | 0    | 32-bit counter 3       |
| 33       | 0    | 32-bit counter 3 (LSB) |

### Counter alarm level

| Register | Page | Description                        |
| -------- | ---- | ---------------------------------- |
| 34       | 0    | 32-bit counter 0 alarm level (MSB) |
| 35       | 0    | 32-bit counter 0 alarm level       |
| 36       | 0    | 32-bit counter 0 alarm level       |
| 37       | 0    | 32-bit counter 0 alarm level (LSB) |
| 38       | 0    | 32-bit counter 1 alarm level (MSB) |
| 39       | 0    | 32-bit counter 1 alarm level       |
| 40       | 0    | 32-bit counter 1 alarm level       |
| 41       | 0    | 32-bit counter 1 alarm level (LSB) |
| 42       | 0    | 32-bit counter 2 alarm level (MSB) |
| 43       | 0    | 32-bit counter 2 alarm level       |
| 44       | 0    | 32-bit counter 2 alarm level       |
| 45       | 0    | 32-bit counter 2 alarm level (LSB) |
| 46       | 0    | 32-bit counter 3 alarm level (MSB) |
| 47       | 0    | 32-bit counter 3 alarm level       |
| 48       | 0    | 32-bit counter 3 alarm level       |
| 49       | 0    | 32-bit counter 3 alarm level (LSB) |

### Counter reload value

| Register | Page | Description                         |
| -------- | ---- | ----------------------------------- |
| 50       | 0    | 32-bit counter 0 reload value (MSB) |
| 51       | 0    | 32-bit counter 0 reload value       |
| 52       | 0    | 32-bit counter 0 reload value       |
| 53       | 0    | 32-bit counter 0 reload value (LSB) |
| 54       | 0    | 32-bit counter 1 reload value (MSB) |
| 55       | 0    | 32-bit counter 1 reload value       |
| 56       | 0    | 32-bit counter 1 reload value       |
| 57       | 0    | 32-bit counter 1 reload value (LSB) |
| 58       | 0    | 32-bit counter 2 reload value (MSB) |
| 59       | 0    | 32-bit counter 2 reload value       |
| 60       | 0    | 32-bit counter 2 reload value       |
| 61       | 0    | 32-bit counter 2 reload value (LSB) |
| 62       | 0    | 32-bit counter 3 reload value (MSB) |
| 63       | 0    | 32-bit counter 3 reload value       |
| 64       | 0    | 32-bit counter 3 reload value       |
| 65       | 0    | 32-bit counter 3 reload value (LSB) |

### Counter hysteresis

| Register | Page | Description                       |
| -------- | ---- | --------------------------------- |
| 66       | 0    | 16-bit counter 0 hysteresis (MSB) |
| 67       | 0    | 16-bit counter 0 hysteresis (LSB) |
| 68       | 0    | 16-bit counter 1 hysteresis (MSB) |
| 69       | 0    | 16-bit counter 1 hysteresis (LSB) |
| 70       | 0    | 16-bit counter 2 hysteresis (MSB) |
| 71       | 0    | 16-bit counter 2 hysteresis (LSB) |
| 72       | 0    | 16-bit counter 3 hysteresis (MSB) |
| 73       | 0    | 16-bit counter 3 hysteresis (LSB) |

### Counter report interval

| Register | Page | Description                                                         |
| -------- | ---- | ------------------------------------------------------------------- |
| 74       | 0    | Report interval for counter 0 in seconds. Set to zero to disable.   |
| 75       | 0    | Report interval for counter 1 in seconds. Set to zero to disable.   |
| 76       | 0    | Report interval for counter 2 in seconds. Set to zero to disable.   |
| 77       | 0    | Report interval for counter 3 in seconds. Set to zero to disable.   |
| 78       | 0    | Report interval for frequency 0 in seconds. Set to zero to disable. |

### Frequency report interval

| Register | Page | Description                                                         |
| -------- | ---- | ------------------------------------------------------------------- |
| 79       | 0    | Report interval for frequency 1 in seconds. Set to zero to disable. |
| 80       | 0    | Report interval for frequency 2 in seconds. Set to zero to disable. |
| 81       | 0    | Report interval for frequency 3 in seconds. Set to zero to disable. |

### Measurements report interval

| Register | Page | Description                                                           |
| -------- | ---- | --------------------------------------------------------------------- |
| 82       | 0    | Report interval for measurement 0 in seconds. Set to zero to disable. |
| 83       | 0    | Report interval for measurement 1 in seconds. Set to zero to disable. |
| 84       | 0    | Report interval for measurement 2 in seconds. Set to zero to disable. |
| 85       | 0    | Report interval for measurement 3 in seconds. Set to zero to disable. |

### Linearization information

<table>
<thead>
<tr class="header">
<th>Register</th>
<th>Page</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>86</td>
<td>0</td>
<td>VSCP event information for linearization counter 0<br />
<br />
<strong>bit 0</strong> - Calculate using counter if zero, frequency if one.<br />
<strong>bit 1</strong> - Reserved.<br />
<strong>bit 2</strong> - Reserved.<br />
<strong>bit 3</strong> - Unit.<br />
<strong>bit 4</strong> - Unit.<br />
<strong>bit 5</strong> - Reserved.<br />
<strong>bit 6</strong> - Class bit 8.<br />
<strong>bit 7</strong> - Enable.<br />
</td>
</tr>
<tr class="even">
<td>87</td>
<td>0</td>
<td>VSCP event information for linearization counter 0, VSCP Class low eight bits</td>
</tr>
<tr class="odd">
<td>88</td>
<td>0</td>
<td>VSCP event information for linearization counter 0, VSCP Type</td>
</tr>
<tr class="even">
<td>89</td>
<td>0</td>
<td>VSCP event information for linearization counter 1<br />
<br />
<strong>bit 0</strong> - Calculate using counter if zero, frequency if one.<br />
<strong>bit 1</strong> - Reserved.<br />
<strong>bit 2</strong> - Reserved.<br />
<strong>bit 3</strong> - Unit.<br />
<strong>bit 4</strong> - Unit.<br />
<strong>bit 5</strong> - Reserved.<br />
<strong>bit 6</strong> - Class bit 8.<br />
<strong>bit 7</strong> - Enable.<br />
</td>
</tr>
<tr class="odd">
<td>90</td>
<td>0</td>
<td>VSCP event information for linearization counter 1, VSCP Class low eight bits</td>
</tr>
<tr class="even">
<td>91</td>
<td>0</td>
<td>VSCP event information for linearization counter 1, VSCP Type</td>
</tr>
<tr class="odd">
<td>92</td>
<td>0</td>
<td>VSCP event information for linearization counter 2<br />
<br />
<strong>bit 0</strong> - Calculate using counter if zero, frequency if one.<br />
<strong>bit 1</strong> - Reserved.<br />
<strong>bit 2</strong> - Reserved.<br />
<strong>bit 3</strong> - Unit.<br />
<strong>bit 4</strong> - Unit.<br />
<strong>bit 5</strong> - Reserved.<br />
<strong>bit 6</strong> - Reserved.<br />
<strong>bit 7</strong> - Class bit 8.<br />
</td>
</tr>
<tr class="even">
<td>93</td>
<td>0</td>
<td>VSCP event information for linearization counter 2, VSCP Class low eight bits</td>
</tr>
<tr class="odd">
<td>94</td>
<td>0</td>
<td>VSCP event information for linearization counter 2, VSCP Type</td>
</tr>
<tr class="even">
<td>95</td>
<td>0</td>
<td>VSCP event information for linearization counter 3<br />
<br />
<strong>bit 0</strong> - Calculate using counter if zero, frequency if one.<br />
<strong>bit 1</strong> - Reserved.<br />
<strong>bit 2</strong> - Reserved.<br />
<strong>bit 3</strong> - Unit.<br />
<strong>bit 4</strong> - Unit.<br />
<strong>bit 5</strong> - Class bit 8.<br />
<strong>bit 6</strong> - Enable.<br />
<strong>bit 7</strong> - Enable.<br />
</td>
</tr>
<tr class="odd">
<td>96</td>
<td>0</td>
<td>VSCP event information for linearization counter 3, VSCP Class low eight bits</td>
</tr>
<tr class="even">
<td>97</td>
<td>0</td>
<td>VSCP event information for linearization counter 3, VSCP Type</td>
</tr>
</tbody>
</table>

## Page 1

### Frequency

| Register | Page | Description                          |
| -------- | ---- | ------------------------------------ |
| 0        | 1    | 32-bit frequency for channel 0 (MSB) |
| 1        | 1    | 32-bit frequency for channel 0       |
| 2        | 1    | 32-bit frequency for channel 0       |
| 3        | 1    | 32-bit frequency for channel 0 (LSB) |
| 4        | 1    | 32-bit frequency for channel 1 (MSB) |
| 5        | 1    | 32-bit frequency for channel 1       |
| 6        | 1    | 32-bit frequency for channel 1       |
| 7        | 1    | 32-bit frequency for channel 1 (LSB) |
| 8        | 1    | 32-bit frequency for channel 2 (MSB) |
| 9        | 1    | 32-bit frequency for channel 2       |
| 10       | 1    | 32-bit frequency for channel 2       |
| 11       | 1    | 32-bit frequency for channel 2 (LSB) |
| 12       | 1    | 32-bit frequency for channel 3 (MSB) |
| 13       | 1    | 32-bit frequency for channel 3       |
| 14       | 1    | 32-bit frequency for channel 3       |
| 15       | 1    | 32-bit frequency for channel 3 (LSB) |

### Frequency low alarm level

| Register | Page | Description                                          |
| -------- | ---- | ---------------------------------------------------- |
| 16       | 1    | 32-bit frequency low alarm level for channel 0 (MSB) |
| 17       | 1    | 32-bit frequency low alarm level for channel 0       |
| 18       | 1    | 32-bit frequency low alarm level for channel 0       |
| 19       | 1    | 32-bit frequency low alarm level for channel 0 (LSB) |
| 20       | 1    | 32-bit frequency low alarm level for channel 1 (MSB) |
| 21       | 1    | 32-bit frequency low alarm level for channel 1       |
| 22       | 1    | 32-bit frequency low alarm level for channel 1       |
| 23       | 1    | 32-bit frequency low alarm level for channel 1 (LSB) |
| 24       | 1    | 32-bit frequency low alarm level for channel 2 (MSB) |
| 25       | 1    | 32-bit frequency low alarm level for channel 2       |
| 26       | 1    | 32-bit frequency low alarm level for channel 2       |
| 27       | 1    | 32-bit frequency low alarm level for channel 2 (LSB) |
| 28       | 1    | 32-bit frequency low alarm level for channel 3 (MSB) |
| 29       | 1    | 32-bit frequency low alarm level for channel 3       |
| 30       | 1    | 32-bit frequency low alarm level for channel 3       |
| 31       | 1    | 32-bit frequency low alarm level for channel 3 (LSB) |

### Frequency high alarm level

| Register | Page | Description                                           |
| -------- | ---- | ----------------------------------------------------- |
| 32       | 1    | 32-bit frequency high alarm level for channel 0 (MSB) |
| 33       | 1    | 32-bit frequency high alarm level for channel 0       |
| 34       | 1    | 32-bit frequency high alarm level for channel 0       |
| 35       | 1    | 32-bit frequency high alarm level for channel 0 (LSB) |
| 36       | 1    | 32-bit frequency high alarm level for channel 1 (MSB) |
| 37       | 1    | 32-bit frequency high alarm level for channel 1       |
| 38       | 1    | 32-bit frequency high alarm level for channel 1       |
| 39       | 1    | 32-bit frequency high alarm level for channel 1 (LSB) |
| 40       | 1    | 32-bit frequency high alarm level for channel 2 (MSB) |
| 41       | 1    | 32-bit frequency high alarm level for channel 2       |
| 42       | 1    | 32-bit frequency high alarm level for channel 2       |
| 43       | 1    | 32-bit frequency high alarm level for channel 2 (LSB) |
| 44       | 1    | 32-bit frequency high alarm level for channel 3 (MSB) |
| 45       | 1    | 32-bit frequency high alarm level for channel 3       |
| 46       | 1    | 32-bit frequency high alarm level for channel 3       |
| 47       | 1    | 32-bit frequency high alarm level for channel 3 (LSB) |

### Frequency hysteresis

| Register | Page | Description                         |
| -------- | ---- | ----------------------------------- |
| 48       | 1    | 16-bit frequency 0 hysteresis (MSB) |
| 49       | 1    | 16-bit frequency 0 hysteresis (LSB) |
| 50       | 1    | 16-bit frequency 1 hysteresis (MSB) |
| 51       | 1    | 16-bit frequency 1 hysteresis (LSB) |
| 52       | 1    | 16-bit frequency 2 hysteresis (MSB) |
| 53       | 1    | 16-bit frequency 2 hysteresis (LSB) |
| 54       | 1    | 16-bit frequency 3 hysteresis (MSB) |
| 55       | 1    | 16-bit frequency 3 hysteresis (LSB) |

## Page 2

### Linearization constants

| Register | Page | Description                                                        |
| -------- | ---- | ------------------------------------------------------------------ |
| 0        | 2    | 32-bit floating point linearization k-constant for channel 0 (MSB) |
| 1        | 2    | 32-bit floating point linearization k-constant for channel 0       |
| 2        | 2    | 32-bit floating point linearization k-constant for channel 0       |
| 3        | 2    | 32-bit floating point linearization k-constant for channel 0 (LSB) |
| 4        | 2    | 32-bit floating point linearization k-constant for channel 1 (MSB) |
| 5        | 2    | 32-bit floating point linearization k-constant for channel 1       |
| 6        | 2    | 32-bit floating point linearization k-constant for channel 1       |
| 7        | 2    | 32-bit floating point linearization k-constant for channel 1 (LSB) |
| 8        | 2    | 32-bit floating point linearization k-constant for channel 2 (MSB) |
| 9        | 2    | 32-bit floating point linearization k-constant for channel 2       |
| 10       | 2    | 32-bit floating point linearization k-constant for channel 2       |
| 11       | 2    | 32-bit floating point linearization k-constant for channel 2 (LSB) |
| 12       | 2    | 32-bit floating point linearization k-constant for channel 3 (MSB) |
| 13       | 2    | 32-bit floating point linearization k-constant for channel 3       |
| 14       | 2    | 32-bit floating point linearization k-constant for channel 3       |
| 15       | 2    | 32-bit floating point linearization k-constant for channel 3 (LSB) |
| 16       | 2    | 32-bit floating point linearization m-constant for channel 0 (MSB) |
| 17       | 2    | 32-bit floating point linearization m-constant for channel 0       |
| 18       | 2    | 32-bit floating point linearization m-constant for channel 0       |
| 19       | 2    | 32-bit floating point linearization m-constant for channel 0 (LSB) |
| 20       | 2    | 32-bit floating point linearization m-constant for channel 1 (MSB) |
| 21       | 2    | 32-bit floating point linearization m-constant for channel 1       |
| 22       | 2    | 32-bit floating point linearization m-constant for channel 1       |
| 23       | 2    | 32-bit floating point linearization m-constant for channel 1 (LSB) |
| 24       | 2    | 32-bit floating point linearization m-constant for channel 2 (MSB) |
| 25       | 2    | 32-bit floating point linearization m-constant for channel 2       |
| 26       | 2    | 32-bit floating point linearization m-constant for channel 2       |
| 27       | 2    | 32-bit floating point linearization m-constant for channel 2 (LSB) |
| 28       | 2    | 32-bit floating point linearization m-constant for channel 3 (MSB) |
| 29       | 2    | 32-bit floating point linearization m-constant for channel 3       |
| 30       | 2    | 32-bit floating point linearization m-constant for channel 3       |
| 31       | 2    | 32-bit floating point linearization m-constant for channel 3 (LSB) |

## Page 3

| Register | Page | Description     |
| -------- | ---- | --------------- |
| 0-31     | 3    | Decision matrix |

  
[filename](./bottom-copyright.md ':include')
