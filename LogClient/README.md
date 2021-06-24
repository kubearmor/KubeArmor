# Log Client

Log client collects the messages, alerts, and system logs from KubeArmor and stores them in the given log files (or prints them in the console).

## Log Client Deployment

You can simply deploy the Log client for KubeArmor.

```
$ cd KubeArmor/LogClient/deployments
~/KubeArmor/LogClient/deployments$ kubectl apply -n [target namespace] -f client-deployment.yaml
```

## Arguments

These are the default arguments.

```
args: ["-msgPath=stdout", "-logPath=stdout", "-logFilter=policy", "-json"]
```

If you want to change the default arguements, you can refer to the following arguments

```
-msgPath={stdout|logFilePath|none}
-logPath={stdout|logFilePath|none}
-logFilter={all|policy|system}
-json (if you want to see the messages, alerts, or logs in a raw format)
```
