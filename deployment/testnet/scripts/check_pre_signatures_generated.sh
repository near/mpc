 for i in {1..5}; do   echo -n "node$i: ";   curl -s http://51.68.219.$i:1808$i/debug/tasks     | awk '/generate presignatures for domain 0/ {
        match($0, /available: ([0-9]+)\/([0-9]+)/, a);
        print a[1] "/" a[2]
      }'; done

 
 
# e.g http://5.196.36.113:18086/debug/tasks
       for i in {6..9}; do   echo -n "node$i: ";   curl -s http://5.196.36.$((113+i-6)):1808$i/debug/tasks     | awk '/generate presignatures for domain 0/ {
        match($0, /available: ([0-9]+)\/([0-9]+)/, a);
        print a[1] "/" a[2]
      }'; done

echo -n "node10: ";   curl -s http://5.196.36.$((113+10-6)):18090/debug/tasks     | awk '/generate presignatures for domain 0/ {
    match($0, /available: ([0-9]+)\/([0-9]+)/, a);
    print a[1] "/" a[2]
      }'
