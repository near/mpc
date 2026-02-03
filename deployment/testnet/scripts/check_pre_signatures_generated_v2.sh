for i in {1..8}; do
  echo -n "node$i: "
  curl -s http://51.68.219.$i:18082/debug/tasks | awk '/generate presignatures for domain 0/ {
    match($0, /available: ([0-9]+)\/([0-9]+)/, a)
    print a[1] "/" a[2]
  }'
done

for i in {10..10}; do
  echo -n "node$i: "
  curl -s http://5.196.36.$((113+i-6)):18082/debug/tasks | awk '/generate presignatures for domain 0/ {
    match($0, /available: ([0-9]+)\/([0-9]+)/, a)
    print a[1] "/" a[2]
  }'
done
