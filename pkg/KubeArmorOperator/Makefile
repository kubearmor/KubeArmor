.PHONY: all
all: get snitch kubearmor-operator


.PHONY: get
get: tidy
	go get

tidy:
	go mod tidy

.PHONY: snitch
snitch: get
	go build -o snitch main.go

.PHONY: kubearmor-operator
kubearmor-operator: get
	go build -o kubearmor-operator main.go

.PHONY: clean
clean:
	rm snitch kubearmor-operator