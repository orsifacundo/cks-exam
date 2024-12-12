# CKS Exam tips

# Guides

- [Official web for the Certified Kubernetes Security Specialist (CKS) certification](https://www.cncf.io/certification/cks/)

- [Guide to Certified Kubernetes Security Specialist (CKS) ](https://teckbootcamps.com/cks-exam-study-guide/) 

- On September 2024 the exam curriculum changed so there are a few things that are different from the old posts you might find. You can get information on some of those changes [here](https://kodekloud.com/blog/cks-exam-updates-2024-your-complete-guide-to-certification-with-kodekloud/)

# CKS Exam Syllabus (Kubernetes 1.31) 
- [Cluster Setup - 10%](#cluster-setup)
- [Cluster Hardening - 15%](#cluster-hardening)
- [System Hardening - 15%](#system-hardening)
- [Minimize Microservice Vulnerabilities - 20%](#minimize-microservice-vulnerabilities)
- [Supply Chain Security - 20%](#supply-chain-security)
- [Monitoring, Logging and Runtime Security - 20%](#monitoring-logging-and-runtime-security)

- [Useful commands](#useful-commands)
- [Resources](#resources)

# Cluster Setup

## Network Policies

- [K8s docs: Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### To/From selectors

There are four kinds of selectors that can be specified in an ingress from section or egress to section:

- podSelector: This selects particular Pods **in the same namespace as** the NetworkPolicy which should be allowed as ingress sources or egress destinations.

- namespaceSelector: This selects particular namespaces for which all Pods should be allowed as ingress sources or egress destinations.

- namespaceSelector and podSelector: A single to/from entry that specifies both namespaceSelector and podSelector selects particular Pods within particular namespaces. Be careful to use correct YAML syntax. For example:

```yaml
  ...
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          user: alice
      podSelector:
        matchLabels:
          role: client
  ...
```

This policy contains a single from element allowing connections from Pods with the label role=client in namespaces with the label user=alice. But the following policy is different:

```yaml
  ...
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          user: alice
    - podSelector:
        matchLabels:
          role: client
  ...
```

It contains two elements in the from array, and allows connections from Pods in the local Namespace with the label role=client, or from any Pod in any namespace with the label user=alice.

### Deny-all Egress but allow outgoing DNS TCP/UDP

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-out
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
```

### How to define namespace selector using different ways

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space1
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: space2

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space2
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: ["space1"]
```

### Except an ip

```yaml
...
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 1.1.1.1/32
...
```

### Network Policies with Cillium

- [[DOC] Cillium network policy examples](https://docs.cilium.io/en/stable/security/policy/)
- [[BLOG] Working with Cillium](https://www.sheddy.xyz/blog/intro-to-kubernetes-networking-with-cilium)

## CIS Benchmarks

### Use of kube-bench

- If installed then just run `kube-bench run --targets master --check CHECK_NUMBER` and it will give you the output and the remediation steps.

## Ingress

- [K8s docs: Ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/)
- [Nginx docs: TLS](https://kubernetes.github.io/ingress-nginx/user-guide/tls/)
- Take into consideration how to HTTP -> HTTPS redirection.

If we have a service that directs to a deployment, we can define an ingress for that service:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: world
  namespace: world
  annotations:
    # this annotation removes the need for a trailing slash when calling urls
    # but it is not necessary for solving this scenario
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx # k get ingressclass
  rules:
  - host: "world.universe.mine"
    http:
      paths:
      - path: /europe
        pathType: Prefix
        backend:
          service:
            name: europe
            port:
              number: 80
      - path: /asia
        pathType: Prefix
        backend:
          service:
            name: asia
            port:
              number: 80
```

### TLS for Ingress

- [K8s docs: Ingress TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)

#### Create a tls secret on an imperative way

` kubectl create secret tls world-tls --cert=path/to/cert/file --key=path/to/key/file`

#### Create a tls secret the hard way

##### Starting with a simple secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: world-tls
  namespace: world
data:
  tls.crt: CERT
  tls.key: KEY
type: kubernetes.io/tls
```

##### You can then create a cert/key:

```shell
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout cert.key -out cert.crt -subj "/CN=world.universe.mine/O=world.universe.mine"
```

##### And base64 encode and replace on the secret:

```shell
cert=$(base64 -w 0 cert.crt); key=$(base64 -w 0 cert.key); sed "s/CERT/$cert/g" secret.yml | sed "s/KEY/$key/g"
```

#### Mount it on the Ingress:

```yaml
...
spec:
  tls:
  - hosts:
      - world.universe.mine
    secretName: world-tls
...
```

## Verify binaries

- If downloading the binaries from the repository then you should extract the content of the tar.gz and obtain hash from X component i.e kubelet
- You can also download the checksum of the binaries directly from the https://kubernetes.io/releases/download/ page
- Then to compare it with the binary that is actually being used you need to search where that file exists on the FS `systemctl status kubelet`or `find / -name "kubelet"`
- A automatic comparison can be done with `echo $(cat HASH-FILE) FILE | sha256sum --check`. It'll tell you OK or FAILED

# Cluster Hardening

## RBAC

### Check permissions

`k auth can-i update deployments --as system:serviceaccount:ns1:pipeline -n ns1`

## Service Accounts
- [K8s docs: Service Accounts](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

### Automounting
- [K8s docs: Automounting](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)

#### In SA:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: build-robot
automountServiceAccountToken: false
...
```

#### In Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: build-robot
  automountServiceAccountToken: false
  ...
```

#### Token path -> `/var/run/secrets/kubernetes.io/serviceaccount/token`

## User authentication

### Certificate creation manually

- [K8s docs: CSRs](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)

#### Generate key, CSR and sign it using K8s CA:

```shell
openssl genrsa -out /root/60099.key 2048
openssl req -new -key /root/60099.key -out /root/60099.csr
openssl x509 -req -in /root/60099.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out /root/60099.crt 
#Answer CN should be the username e.g 60099@internal.users
```

#### Add user and context on kubeconfig:

```shell
kubectl config set-credentials 60099@internal.users --client-certificate=/root/60099.crt --client-key=/root/60099.key --embed-certs=true
kubectl config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
```

### Certificate creation via K8s API

- [K8s docs: Manage TLS in a Cluster](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/)
- [K8s docs: Kubernetes Signers](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers)

#### Generate key and CSR:

```shell
openssl genrsa -out /root/60099.key 2048
openssl req -new -key /root/60099.key -out /root/60099.csr
```

#### Create a CSR K8s object, approved it to issue the cert and export it:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: 60099@internal.users
spec:
  request: $(cat /root/60099.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

kubectl certificate approve 60099@internal.users #The STATUS should be APPROVED,ISSUED if executing 'kubectl get csr 60099@internal.users'
kubectl get csr 60099@internal.users -o jsonpath='{.status.certificate}' | base64 --decode > /root/60099.crt
```

#### Add user and context on kubeconfig:

```shell
kubectl config set-credentials 60099@internal.users --client-certificate=/root/60099.crt --client-key=/root/60099.key --embed-certs=true
kubectl config set-context 60099@internal.users --cluster=kubernetes --user=60099@internal.users
```

## Enable NodeRestriction admission controller

- On nodes you can execute commands against the K8s API impersonating the kubelet by `export KUBECONFIG=/etc/kubernetes/kubelet.conf``
- If the NodeRestriction admission controller is not active then nodes can add labels to other nodes. To activate:
  - Add `--enable-admission-plugins=NodeRestriction` to the kube-apiserver manifest

## Troubleshooting

- Location of controlplane components manifests `/etc/kubernetes/manifests/`

- If problems with kube-apiserver then:
  - Check `/var/log/pods/kube-system_kube-apiserver-controlplane*/...`on the master node for errors
  - Use `crictl` or `podman` or `docker` + `logs` on the appropiate container to check the logs.
  - `journalctl -xe -g apiserver`  


# System Hardening

## Minimize host OS footprint (reduce attack surface)

- `ps -fea`
- `ss -npl` o `netstat -npl`
- `ls -l /proc/PID`
- `strace -p PID -f -cw`
  - `-f`follow forks
  - `-cw` summarize calls

## Appropriately use kernel hardening tools such as AppArmor, seccomp

### AppArmor

#### Check status

- Check if enabled `cat /sys/module/apparmor/parameters/enabled`
- Check loaded profiles on node `cat /sys/kernel/security/apparmor/profiles`
- Or simply run `apparmor_status`

#### Load into pods/containers

```yaml
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: NAME-PROFILE
```

#### Check it's loaded on the container

- `kubectl exec XXXX -- cat /proc/1/attr/current`
- On node where pods is: `crictl inspect CONTAINER-ID | grep apparmor`

#### Install a new profile

- `apparmor_parser PATH_TO_PROFILE`
- Copy profile into `/etc/apparmor.d`

# Minimize Microservice Vulnerabilities

## Manage Kubernetes secrets

### Obtain secrets value

`kubectl get secret s3 -ojsonpath="{.data.data}" | base64 -d`

### Secret ETCD Encryption

- [K8s docs: Encrypt Secrets](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

#### Generate a file for the config provider

- This will encrypt NEW secrets (as the `awsgcm` provider is first)
- Unecrypted secrets still can be read (as the `identity: {}` provider is second)

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: dGhpcy1pcy12ZXJ5LXNlYw==
    - identity: {}
```

#### Add the reference to the file in the kube-apiserver manifest

- Add the `encryption-provider-config` parameter
- Add a volume with hostPath
- Reference this volume as volumeMount

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
...
    - --encryption-provider-config=/etc/kubernetes/etcd/ec.yaml
...
    volumeMounts:
    - mountPath: /etc/kubernetes/etcd
      name: etcd
      readOnly: true
...
  volumes:
  - hostPath:
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate
    name: etcd
...
```
#### Encrypt existing secrets

`kubectl -n one get secrets -o json | kubectl replace -f -`

- Check with: `ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/one/s1`

### Secret Access in Pods

- [K8s docs: Use Secrets](https://kubernetes.io/docs/tasks/inject-data-application/distribute-credentials-secure/)

#### Create secrets

`kubectl create secret generic holy --from-literal creditcard=1111222233334444`

#### Use them in pods

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  volumes:
  - name: diver
    secret:
      secretName: diver
  containers:
  - image: nginx
    name: pod1
    volumeMounts:
      - name: diver
        mountPath: /etc/diver
    env:
      - name: HOLY
        valueFrom:
          secretKeyRef:
            name: holy
            key: creditcard
```

## Understand and implement isolation techniques (multi-tenancy, sandboxed containers, etc.)

### Use sandboxed containers (i.e: gvisor, kata)

- [K8s docs: Runtime Classes](https://kubernetes.io/docs/concepts/containers/runtime-class/)

#### Define the configuration for the runtime (for containerd in `/etc/containerd/config.toml`)

```
version = 3
[plugins."io.containerd.cri.v1.runtime".containerd]
  default_runtime_name = "gvisor"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes]
    # gVisor: https://gvisor.dev/
    [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.gvisor]
      runtime_type = "io.containerd.runsc.v1"
```

#### Create a RuntimeClass

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisorClass
handler: gvisor
```

#### Use the RuntimeClass on the pod.spec

```yaml
apiVersion: v1
kind: Pod
spec:
  runtimeClassName: gvisorClass
```

#### Verificar que se cargó correctamente el sandbox

`kubectl exec <pod> -- dmesg`

## Implement Pod-to-Pod encryption using Cilium

- [[DOC] Cillium mutual authentication](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication-example/#enforce-mutual-authentication)
- [[EXAMPLE] Cillium mutual authentication](https://raw.githubusercontent.com/cilium/cilium/1.16.4/examples/kubernetes/servicemesh/cnp-with-mutual-auth.yaml)

# Supply Chain Security

## Understand your supply chain

- [BOM docs: Usage](https://kubernetes-sigs.github.io/bom/cli-reference/bom_generate/)

### Usage

- By default the output is SPDX format

`bom generate --image <<IMAGE>> --format json --output <<FILE>>`

## Secure your supply chain

### ImagePolicyWebhook admission controller

- [K8s docs: ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)

#### Add parameters on `kube-apiserver.yaml`manifest 

```yaml
apiVersion: v1
kind: Pod
metadata:
  ...
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
  - command:
    - kube-apiserver
    ...
    - --enable-admission-plugins=ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.json
    ...
```

#### Admission configuration file format

```json
{
   "apiVersion": "apiserver.config.k8s.io/v1",
   "kind": "AdmissionConfiguration",
   "plugins": [
      {
         "name": "ImagePolicyWebhook",
         "configuration": {
            "imagePolicy": {
               "kubeConfigFile": "/etc/kubernetes/policywebhook/kubeconf",
               "allowTTL": 100,
               "denyTTL": 50,
               "retryBackoff": 500,
               "defaultAllow": false
            }
         }
      }
   ]
}
```

### Image digest 

- Obtain the image digest of a pod `k get pod XXX -oyaml | grep imageID`

## Perform static analysis of user workloads and container images

- You should feel comfortable analysing Dockerfiles and K8s manifest files for security improvements.
- [KubeLinter docs: Usage](https://docs.kubelinter.io/?ref=kodekloud.com#/using-kubelinter)
- [Kubesec docs: Usage](https://kubesec.io/#usage-example)

# Monitoring, Logging and Runtime Security

## Perform behavioral analytics to detect malicious activities

### Falco

- Rules live in `/etc/falco/`
- After changes the service has to be restarted
- Supported fields: https://falco.org/docs/reference/rules/supported-fields/
- Manual execution of Falco using `falco -r <RULE_FILE> -M 45`

## Use Kubernetes audit logs to monitor access

- [K8s docs: Audit](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

### Audit

#### Create an audit policy file with the proper rules

- **None** - don't log events that match this rule.
- **Metadata** - log events with metadata (requesting user, timestamp, resource, verb, etc.) but not request or response body.
- **Request** - log events with request metadata and body but not response body. This does not apply for non-resource requests.
- **RequestResponse** - log events with request metadata, request body and response body. This does not apply for non-resource requests.

```yaml
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
```

#### Configure the kube-apiserver manifest

```yaml
# enable Audit Logs
spec:
  containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit-policy/policy.yaml
    - --audit-log-path=/etc/kubernetes/audit-logs/audit.log
    - --audit-log-maxsize=7
    - --audit-log-maxbackup=2
...
# add new VolumeMounts
volumeMounts:
  - mountPath: /etc/kubernetes/audit-policy/policy.yaml
    name: audit-policy
    readOnly: true
  - mountPath: /etc/kubernetes/audit-logs
    name: audit-logs
    readOnly: false
...
# add new Volumes
volumes:
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit-policy/policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /etc/kubernetes/audit-logs
      type: DirectoryOrCreate

```

# Useful commands

```shell
export die="--force --grace-period 0"
export out="--dry-run=client -oyaml"
export ns="kubectl config set-context --current --namespace" #Then $ns XXX
```

# Resources

- [[DOC] CKS Exam accepted docs](https://docs.linuxfoundation.org/tc-docs/certification/certification-resources-allowed#certified-kubernetes-security-specialist-cks)
- [[VIDEO] Kubernetes CKS Full Course](https://www.youtube.com/watch?v=d9xfB5qaOfg)
- [[COURSE] A Cloud Guru CKS](https://learn.acloud.guru/course/certified-kubernetes-security-specialist/dashboard)
- [[REPO] Kubernetes CKS Full Course](https://github.com/killer-sh/cks-course-environment)
- [[REPO] Kubernetes CKS Full Course resources](https://github.com/killer-sh/cks-course-environment/blob/master/Resources.md)
- [[HANDS-ON] Killercoda scenarios](https://killercoda.com/killer-shell-cks)
- [[TOOL] Network Policy Editor](https://editor.networkpolicy.io/)


