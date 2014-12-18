*bridge;test-bridge

# filter chains available are: prerouting, input, output, forward, postrouting
:filter-pre;type filter hook input priority 0
:filter-output;type filter hook output priority 0
:filter-forward;type filter hook forward priority 0
:filter-input;type filter hook input priority 0
:filter-post;type filter hook input priority 0
