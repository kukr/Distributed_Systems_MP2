# Distributed Group Membership

## For running the server

	$ go run main.go

## For using command line too
Run the following command as specified below

	$ go run cli_query.go [ list_mem | list_self | join | leave ]

## Configuration is present in config.json which contains the following details. Please modify it accordingly

	{
	    "ip": "172.22.94.178",
        "port": 8001,
    	"ping_timeout": 200,
    	"period_time": 200,
    	"dissemination_timeout": 600,
    	"fail_timeout": 400,
    	"ttl": 2,
    	"log_path": "$GOPATH/Distributed_Systems_MP2/vm.log",
    	"introducer_ip": "172.22.94.178"
	}

