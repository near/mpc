 for i in {1..6}; do   echo -n "node$i: ";   curl -s http://51.68.219.$i:1808$i/debug/tasks     | awk '/generate presignatures for domain 0/ {
        match($0, /available: ([0-9]+)\/([0-9]+)/, a);
        print a[1] "/" a[2]
      }'; done