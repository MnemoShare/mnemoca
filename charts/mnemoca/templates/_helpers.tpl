{{- define "mnemoca.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mnemoca.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "mnemoca.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "mnemoca.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "mnemoca.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mnemoca.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: ca
{{- end -}}

{{- define "mnemoca.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mnemoca.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "mnemoca.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "mnemoca.isMongo" -}}
{{- if eq .Values.store.type "mongo" -}}true{{- end -}}
{{- end -}}

{{- define "mnemoca.passphraseSecretName" -}}
{{- default (printf "%s-passphrase" (include "mnemoca.fullname" .)) .Values.passphrase.existingSecret -}}
{{- end -}}

{{- define "mnemoca.tlsSecretName" -}}
{{- default (printf "%s-tls" (include "mnemoca.fullname" .)) .Values.tls.existingSecret -}}
{{- end -}}

{{- define "mnemoca.externalUrl" -}}
{{- if .Values.externalUrl -}}
{{- .Values.externalUrl -}}
{{- else if and .Values.ingress.enabled .Values.ingress.hosts -}}
{{- printf "https://%s" (index .Values.ingress.hosts 0).host -}}
{{- end -}}
{{- end -}}

{{/* Cross-field validation; included once from the Deployment. */}}
{{- define "mnemoca.validate" -}}
{{- if not (has .Values.store.type (list "bolt" "mongo")) -}}
{{- fail (printf "store.type must be bolt or mongo, got %q" .Values.store.type) -}}
{{- end -}}
{{- if and (eq .Values.store.type "bolt") (ne (int .Values.replicaCount) 1) -}}
{{- fail (printf "replicaCount=%d is invalid with store.type=bolt: the embedded store is single-writer. Set replicaCount=1, or use store.type=mongo for HA." (int .Values.replicaCount)) -}}
{{- end -}}
{{- if and (eq .Values.store.type "bolt") (not .Values.persistence.enabled) -}}
{{- fail "store.type=bolt requires persistence.enabled=true: the CA database and keys would be lost on restart." -}}
{{- end -}}
{{- if and (not .Values.passphrase.existingSecret) (not .Values.passphrase.generate) -}}
{{- fail "set passphrase.existingSecret, or passphrase.generate=true for evaluation only (offline rendering such as helm template or Argo CD would otherwise generate a new passphrase and lose access to the root)." -}}
{{- end -}}
{{- if and .Values.tls.enabled (not .Values.tls.existingSecret) (not .Values.tls.generate) -}}
{{- fail "set tls.existingSecret, or tls.generate=true for a self-signed evaluation certificate, or tls.enabled=false." -}}
{{- end -}}
{{- if eq .Values.store.type "mongo" -}}
{{- if .Values.passphrase.generate -}}
{{- fail "passphrase.generate is not supported with store.type=mongo." -}}
{{- end -}}
{{- if not .Values.store.mongo.uriSecret.name -}}
{{- fail "store.type=mongo requires store.mongo.uriSecret.name (a Secret holding the MongoDB URI)." -}}
{{- end -}}
{{- if not .Values.passphrase.existingSecret -}}
{{- fail "store.type=mongo requires passphrase.existingSecret: the root bootstrap Job runs before chart-managed Secrets exist, and every replica must share the passphrase." -}}
{{- end -}}
{{- end -}}
{{- if and (eq .Values.store.type "mongo") (not .Values.operatorApiKey.existingSecret) -}}
{{- fail "store.type=mongo requires operatorApiKey.existingSecret: replicas cannot share an auto-minted key file, and the key is never logged." -}}
{{- end -}}
{{- if and .Values.networkPolicy.acmeEgress.enabled (empty .Values.networkPolicy.acmeEgress.to) -}}
{{- fail "networkPolicy.acmeEgress.to must not be empty when acmeEgress is enabled: an empty list would open port 80 to every destination, including internal networks." -}}
{{- end -}}
{{- if .Values.pkcs11.enabled -}}
{{- if not (and .Values.pkcs11.modulePath .Values.pkcs11.tokenLabel .Values.pkcs11.pinSecret.name) -}}
{{- fail "pkcs11.enabled requires pkcs11.modulePath, pkcs11.tokenLabel and pkcs11.pinSecret.name." -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Environment shared by the server and the init step. */}}
{{- define "mnemoca.env" -}}
- name: GODEBUG
  value: {{ ternary "fips140=on" "fips140=off" .Values.fips.enabled | quote }}
- name: MNEMOCA_DATA
  value: /data
- name: MNEMOCA_DB
  value: {{ .Values.store.type | quote }}
{{- if eq .Values.store.type "mongo" }}
- name: MNEMOCA_MONGO_DATABASE
  value: {{ .Values.store.mongo.database | quote }}
- name: MNEMOCA_MONGO_URI
  valueFrom:
    secretKeyRef:
      name: {{ .Values.store.mongo.uriSecret.name }}
      key: {{ .Values.store.mongo.uriSecret.key }}
{{- end }}
{{- if .Values.pkcs11.enabled }}
- name: MNEMOCA_PKCS11_MODULE
  value: {{ .Values.pkcs11.modulePath | quote }}
- name: MNEMOCA_PKCS11_TOKEN
  value: {{ .Values.pkcs11.tokenLabel | quote }}
- name: MNEMOCA_PKCS11_PIN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.pkcs11.pinSecret.name }}
      key: {{ .Values.pkcs11.pinSecret.key }}
{{- with .Values.pkcs11.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}
{{- with .Values.env }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "mnemoca.initArgs" -}}
- init
- --if-needed
- --passphrase-file=/etc/mnemoca/passphrase/{{ .Values.passphrase.existingSecretKey }}
- {{ printf "--name=%s" .Values.init.name | quote }}
- --alg={{ .Values.init.alg }}
{{- if .Values.init.pairAlg }}
- --pair-alg={{ .Values.init.pairAlg }}
{{- end }}
{{- if .Values.init.experimentalComposite }}
- --experimental-composite
{{- end }}
{{- end -}}

{{/* Volumes/mounts for the init step: passphrase, data, tmp. */}}
{{- define "mnemoca.initContainerBody" -}}
image: {{ include "mnemoca.image" . }}
imagePullPolicy: {{ .Values.image.pullPolicy }}
args:
{{- include "mnemoca.initArgs" . | nindent 2 }}
env:
{{- include "mnemoca.env" . | nindent 2 }}
securityContext:
  {{- toYaml .Values.securityContext | nindent 2 }}
resources:
  {{- toYaml .Values.init.resources | nindent 2 }}
volumeMounts:
  - {name: data, mountPath: /data}
  - {name: tmp, mountPath: /tmp}
  - {name: passphrase, mountPath: /etc/mnemoca/passphrase, readOnly: true}
{{- with .Values.extraVolumeMounts }}
{{ toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "mnemoca.passphraseVolume" -}}
- name: passphrase
  secret:
    secretName: {{ include "mnemoca.passphraseSecretName" . }}
    defaultMode: 0400
{{- end -}}

{{- define "mnemoca.operatorKeyVolume" -}}
{{- if .Values.operatorApiKey.existingSecret -}}
- name: operator-key
  secret:
    secretName: {{ .Values.operatorApiKey.existingSecret }}
    defaultMode: 0400
{{- end -}}
{{- end -}}
