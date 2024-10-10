## Scaling capabilities
Currently chain signatures operates using one signature genertion network and can handle up to 8 concurent requests. Average response time is 15 seconds. We are planning to improve both metrics and scale the system to multiple networks wich will allow to handle more requests and reduce response time.

## Security properties
Chain signatures is usign cait-sith threshold ECDSA protocol. Currently our network consist of 8 nodes with treshold 5. This means that at least 5 nodes must collaborate in order to create a valid signature.