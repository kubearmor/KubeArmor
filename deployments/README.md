## KubeArmor Deployments

This directory hosts the generated, environment specific, YAML deployment files in the respective folders.

### Generate/Update Deployments

- Add/Update Enviroment
    Make changes in `defaults.go`
- Generic changes to various k8s objects and environment agnostic
    Make changes in `objects.go`

```bash
make
```
This will override the existing `yaml` deployments in their respective folders based on updated configuration

