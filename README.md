# Pytunneler

## server

`python -m pytunneler.client.client --password SECRETPASSWORD 0.0.0.0:8321`

## client

`python -m pytunneler.client.client --password SECRETPASSWORD 127.0.0.1:8321`

**command**
|name | description |trigger |
|---------------- | ---------------------------------- |------ |
|List of Commands | List of Commands | lsc |
|List of Ports | List of Ports | lsp |
|TcpTunneling | make a tcp socket tunnel to server |tcptunnel|
