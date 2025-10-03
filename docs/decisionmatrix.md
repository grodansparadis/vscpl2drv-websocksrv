

The full functionality of the decision matrix is explained [in the
specification](http://www.vscp.org/docs/vscpspec/doku.php?id=decision_matrix).

The module have a decision matrix consisting of eight entries. This
matrix can be used to control the I/O channels. Possible actions are
listed in the table below.

| Action     | Action code | Parameter   | Description                                                                                  |
| ---------- | ----------- | ----------- | -------------------------------------------------------------------------------------------- |
| **NOOP**   | 0           | Not used    | No operation. Will do absolutely nothing.                                                    |
| **START**  | 1           | Counter 0-3 | Start counter.                                                                               |
| **STOP**   | 2           | Counter 0-3 | Stop counter.                                                                                |
| **CLEAR**  | 3           | Counter 0-3 | Set counter to zero.                                                                         |
| **RELOAD** | 4           | Counter 0-3 | Reload counter value.                                                                        |
| **COUNT**  | 5           | Counter 0-3 | Count one step for the selected counter. Up or down depends on the settings for the counter. |

  
[filename](./bottom-copyright.md ':include')
