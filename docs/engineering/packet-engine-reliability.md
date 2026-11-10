# Packet engine reliability and diagnostics

## Lifecycle ownership

Windows controller start and stop transitions use one AsyncTransitionLock. The controller's lifetime cancellation source is cancelled by the serialized stop path after network restoration has been attempted; packet-capture and packet-processing tasks are awaited before their native handles are closed.

A background task that faults unexpectedly is reported with its component name and exception, forwarding is disabled, and the controller enters a safe-shutdown path. LANtern does not silently restart the controller or continue to display an active/healthy state after an enforcement failure.

Automatic inventory refresh uses the Windows neighbor cache. Full-subnet discovery is reserved for an explicit manual scan. Errors in periodic presence probes and optional name resolution are observed and reported without being allowed to escape as unobserved background-task failures.

## Packet pipeline

The Windows ARP and IPv4 receive paths each use their own capture handle and dedicated reader. A third Npcap handle is opened for injection only; it is never started for capture and is the only handle used by the serialized sender. The capture reader copies captured frames into a byte-bounded queue; a second dedicated worker parses and applies the traffic policy. Npcap injection uses a priority queue for ARP/control frames and a bounded queue for forwarded traffic.

If a native send fails, LANtern records the error and attempts one bounded reopen of the dedicated injection handle. The original packet is retried through the existing retry policy. Capture handles are left alone. If injection still fails, the supervised failure path disables enforcement and performs a safe shutdown rather than leaving the UI to claim that restrictions are active.

The queue budgets are 32 MiB for captured frames, 32 MiB for forwarded injection, and 1 MiB for ARP/control injection. The budgets prevent memory growth from becoming unbounded. Reaching a budget causes an explicit drop/fault signal; it is not treated as successful forwarding.

Forwarded-packet send retries use a shorter delay than ARP/control retries so a transient forwarding send error does not keep the injection worker from servicing queued ARP enforcement for an extended interval. An unrecoverable injection failure is reported and triggers safe shutdown.

## Health and diagnostics

The UI distinguishes controller state from enforcement health. Running means the controller lifecycle still owns active resources or is in a transition. Active is shown only when the ARP and IPv4 capture handles and the dedicated injection handle are open, the supervised loops are alive, the loaded capture library can be identified, capture statistics are readable, and there is no outstanding health fault or queue-pressure warning. When a device has an active interception policy, the most recent successful ARP injection must also be recent; an open handle without successful enforcement traffic is not considered healthy. A controller may remain Running while visibly Degraded.

The packet-health panel reports:

- SharpPcap and capture-library versions, the loaded wpcap.dll path and file version when available.
- Captured and forwarded packet/byte rates and LANtern process CPU share.
- Npcap kernel capture drops, application capture/injection queue drops, and send/retry counts.
- Capture, forwarding-injection, and ARP-priority queue occupancy.
- Dedicated injection-handle open state, reopen count, and last recovery time.
- Measured ARP and forwarding injection queue wait times and the last successful capture/injection timestamps.

Capture statistics are sampled every two seconds. Queue pressure is reported before a queue is full; actual queue overflow is counted and marks enforcement health degraded. Independent health faults are tracked separately so recovery of one queue does not clear a simultaneous Npcap-drop or statistics fault.

Lifecycle and packet-health transitions are appended as JSON Lines to:

%LOCALAPPDATA%\LANternControl\logs\engine-diagnostics.jsonl

Each entry records a UTC timestamp, event, component, adapter, state, reason, and exception details when present. Logging failure is intentionally isolated from packet forwarding and network restoration.

## Current validation boundary

The automated tests cover the lifecycle transition lock, supervisor behavior, shutdown ordering and failure handling, byte-bounded capture queue, priority injection ordering and retry behavior, recoverable health-state transitions, stale-ARP detection, independent health faults, and structured diagnostics.

A Windows build and installer compilation validate packaging and dependency integration. They do not prove Npcap driver reliability during a sustained gaming workload. The following still require a live Windows network test on the target adapter:

1. Run the controller for an extended period while generating sustained bidirectional Wi-Fi traffic and record packet rates, CPU, Npcap drops, queue occupancy, and injection latency.
2. Repeat with the adapter reset or temporarily disconnected, then verify that LANtern reports the failure and can be stopped/restarted without rebooting Windows.
3. Confirm paused-device enforcement with an independent client under that same load, including after the driver/adapter has recovered.
4. Inspect the actual wpcap.dll path/version shown by the running application and correlate any PacketSendPacket error with the Npcap and MediaTek driver event logs.

No Npcap fork or kernel-driver change is included. Those changes should only be considered after a minimal reproducer proves that a specific driver-level behavior, rather than LANtern's capture/processing/injection scheduling, is responsible.
