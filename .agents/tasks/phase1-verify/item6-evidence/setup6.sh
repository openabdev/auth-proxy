#!/bin/sh
# Run on mini. Creates ns ap-item6 with the stub, secrets and configmaps. No value is printed.
set -eu
K="sudo -n k3s kubectl"; NS=ap-item6; B=/tmp/ap-item6-build
mkdir -p $B/pki $B/keys; cd $B
# PKI for the stub (test only)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=ap-item6-test-ca" -keyout pki/ca.key -out pki/ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=stub" -keyout pki/key.pem -out pki/csr.pem 2>/dev/null
printf 'subjectAltName=DNS:runtime.us-east-1.kiro.dev,DNS:control-plane.placeholder.example\n' > pki/ext
openssl x509 -req -in pki/csr.pem -CA pki/ca.pem -CAkey pki/ca.key -CAcreateserial -days 2 -extfile pki/ext -out pki/cert.pem 2>/dev/null
# keys: caller key + surrogate via the shipped script; dummy "real" credential
sh src/deploy/k8s/interim-keygen.sh $B/keys/k > keys/keygen.out
CH=$(sed -n 's/.*caller_key_sha256 = "\([0-9a-f]*\)".*/\1/p' keys/keygen.out)
SH=$(sed -n 's/.*--interim-static-surrogate-sha256=\([0-9a-f]*\)$/\1/p' keys/keygen.out)
printf 'real-dummy-%s' "$(openssl rand -hex 24)" > keys/real
echo "$CH" > keys/caller.hash; echo "$SH" > keys/surrogate.hash
# policy: example + caller hash + test-only port 8443 on both routes
sed -e "s/^caller_key_sha256 = \"[0-9a-f]*\".*/caller_key_sha256 = \"$CH\"/" \
    -e 's/^host = \(.*\)$/host = \1\nport = 8443/' src/deploy/k8s/policy.example.toml > policy.toml
$K create ns $NS
$K label ns $NS pod-security.kubernetes.io/enforce=privileged
$K -n $NS create configmap auth-proxy-policy --from-file=policy.toml=policy.toml
$K -n $NS create configmap ap-ca --from-file=ca.pem=pki/ca.pem
$K -n $NS create configmap stub-pki --from-file=cert.pem=pki/cert.pem --from-file=key.pem=pki/key.pem
$K -n $NS create configmap stub-code --from-file=stub.py=/tmp/ap-item6-build/stub.py
$K -n $NS create secret generic auth-proxy-kiro --from-file=api_key=keys/real
$K -n $NS create secret generic auth-proxy-interim-agent --from-file=caller-key=keys/k/caller-key --from-file=surrogate=keys/k/surrogate
cat > stub.yaml <<Y
apiVersion: v1
kind: Pod
metadata: {name: stub, labels: {app: ap-item6-stub}}
spec:
  automountServiceAccountToken: false
  containers:
  - name: stub
    image: docker.io/ap-item6/agent:dev
    imagePullPolicy: Never
    command: ["python3","-u","/opt/stub/stub.py"]
    volumeMounts:
    - {name: code, mountPath: /opt/stub}
    - {name: pki, mountPath: /etc/stub-pki}
    - {name: real, mountPath: /run/secrets/real}
  volumes:
  - {name: code, configMap: {name: stub-code}}
  - {name: pki, configMap: {name: stub-pki}}
  - {name: real, secret: {secretName: auth-proxy-kiro}}
---
apiVersion: v1
kind: Service
metadata: {name: stub}
spec: {selector: {app: ap-item6-stub}, ports: [{port: 8443, targetPort: 8443}]}
Y
$K -n $NS apply -f stub.yaml
$K -n $NS wait --for=condition=Ready pod/stub --timeout=90s
$K -n $NS get svc stub -o jsonpath='{.spec.clusterIP}' > keys/stub.ip
echo "setup done; stub ip $(cat keys/stub.ip)"
