#### **Getting Started**

##### **Scan k8s services**
For k8s, the solution gets deployed as a job that scans the k8s service ports.

Clone the GitHub repo link: https://github.com/kubearmor/k8tls
```sh
Git clone https://github.com/kubearmor/k8tls.git
```

```sh
kubectl apply -f https://raw.githubusercontent.com/kubearmor/k8tls/main/k8s/job.yaml
kubectl logs -n k8tls $(kubectl get pod -n k8tls -l job-name=k8tls -o name) -f
```
