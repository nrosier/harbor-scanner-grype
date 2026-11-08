{{/*
Name of the chart (stable prefix for names/labels).
*/}}
{{- define "harbor-scanner-grype.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "harbor-scanner-grype.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart label value.
*/}}
{{- define "harbor-scanner-grype.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "harbor-scanner-grype.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harbor-scanner-grype.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "harbor-scanner-grype.labels" -}}
helm.sh/chart: {{ include "harbor-scanner-grype.chart" . }}
{{ include "harbor-scanner-grype.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Adapter image reference (<repository>:<tag or appVersion>).
*/}}
{{- define "harbor-scanner-grype.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/*
Name of the ServiceAccount to use.
*/}}
{{- define "harbor-scanner-grype.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- printf "%s" (include "harbor-scanner-grype.fullname" .) -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Grype DB location env vars. Both point inside the writable grype-db
emptyDir so a read-only root filesystem is safe. Used by the init
container (grype db update) and inherited by the adapter (which passes
the process env to the grype child).
*/}}
{{- define "harbor-scanner-grype.dbEnv" -}}
- name: GRYPE_DB_CACHE_DIR
  value: {{ .Values.dbCacheDir | quote }}
# grype resolves ~/.cache and ~/.grype.yaml via HOME; point it at the only
# writable path so it never touches the read-only root filesystem.
- name: HOME
  value: {{ .Values.dbCacheDir | quote }}
- name: GRYPE_CHECK_FOR_APP_UPDATE
  value: "false"
{{- end -}}

{{/*
Environment for the adapter container: SCANNER_* from values.config plus the
Grype DB location env vars.
*/}}
{{- define "harbor-scanner-grype.scannerEnv" -}}
- name: SCANNER_API_ADDR
  value: {{ .Values.config.apiAddr | quote }}
- name: SCANNER_SCAN_TIMEOUT
  value: {{ .Values.config.scanTimeout | quote }}
- name: SCANNER_JOB_TTL
  value: {{ .Values.config.jobTTL | quote }}
- name: SCANNER_REGISTRY_INSECURE_SKIP_TLS
  value: {{ .Values.config.registryInsecureSkipTLS | quote }}
- name: SCANNER_REGISTRY_USE_HTTP
  value: {{ .Values.config.registryUseHTTP | quote }}
- name: SCANNER_GRYPE_DB_AUTO_UPDATE
  value: {{ .Values.config.grypeDBAutoUpdate | quote }}
- name: SCANNER_DB_UPDATE_INTERVAL
  value: {{ .Values.config.dbUpdateInterval | quote }}
- name: SCANNER_PREFER_CVE
  value: {{ .Values.config.preferCVE | quote }}
- name: SCANNER_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: SCANNER_WORKER_CONCURRENCY
  value: {{ .Values.config.workerConcurrency | quote }}
- name: SCANNER_SYFT_PATH
  value: {{ .Values.config.syftPath | quote }}
# Syft needs writable paths under the read-only root filesystem. The image is
# distroless (no shell to mkdir), so TMPDIR is the volume root itself; Syft
# creates its cache dir on demand and falls back to in-memory on failure.
- name: TMPDIR
  value: {{ .Values.dbCacheDir | quote }}
- name: SYFT_CACHE_DIR
  value: {{ printf "%s/syft-cache" (.Values.dbCacheDir | trimSuffix "/") | quote }}
- name: SYFT_CHECK_FOR_APP_UPDATE
  value: "false"
{{ include "harbor-scanner-grype.dbEnv" . }}
{{- end -}}

{{/*
volumeMount for the Grype DB cache (writable emptyDir).
*/}}
{{- define "harbor-scanner-grype.dbMount" -}}
- name: grype-db
  mountPath: {{ .Values.dbCacheDir | quote }}
{{- end -}}
