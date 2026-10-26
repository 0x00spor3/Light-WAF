{{/* SPDX-License-Identifier: Apache-2.0 */}}

{{- define "wafcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wafcp.fullname" -}}
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

{{- define "wafcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels — component is set per-resource (control-plane / postgres / redis) */}}
{{- define "wafcp.labels" -}}
helm.sh/chart: {{ include "wafcp.chart" . }}
{{ include "wafcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "wafcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wafcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "wafcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "wafcp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "wafcp.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "wafcp.postgresFullname" -}}
{{- printf "%s-postgres" (include "wafcp.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "wafcp.redisFullname" -}}
{{- printf "%s-redis" (include "wafcp.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The Secret name the Deployment loads WAF_CP_* env from (chart-created unless existingSecret) */}}
{{- define "wafcp.secretName" -}}
{{- default (printf "%s-env" (include "wafcp.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "wafcp.postgresAuthSecret" -}}
{{- printf "%s-auth" (include "wafcp.postgresFullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Decoded value of key `key` in Secret `name` of namespace `ns`, or "" (no cluster access
     under `helm template`, Secret absent, or key absent). */}}
{{- define "wafcp.lookupSecretKey" -}}
{{- $s := lookup "v1" "Secret" .ns .name -}}
{{- if and $s $s.data (hasKey $s.data .key) -}}
{{- index $s.data .key | b64dec -}}
{{- end -}}
{{- end -}}

{{/* Resolve credentials the user left empty: reuse the value already stored in the cluster
     (upgrade), else generate a random one (first install). Writes the result back into
     .Values so every template of this render sees the SAME value; idempotent (a resolved
     value is non-empty, so later calls keep it). Names resolved here are recorded in
     .Values._wafcpAutoManaged for the NOTES. Include it in every template that reads
     secrets.apiToken / secrets.bootstrapAdminPassword / postgres.bundled.password. */}}
{{- define "wafcp.resolveSecrets" -}}
{{- if not (hasKey .Values "_wafcpAutoManaged") -}}
{{- $_ := set .Values "_wafcpAutoManaged" (list) -}}
{{- end -}}
{{- $ns := .Release.Namespace -}}
{{- if not .Values.secrets.existingSecret -}}
{{- $env := printf "%s-env" (include "wafcp.fullname" .) -}}
{{- if not .Values.secrets.apiToken -}}
{{- $v := include "wafcp.lookupSecretKey" (dict "ns" $ns "name" $env "key" "WAF_CP_API_TOKEN") -}}
{{- $_ := set .Values.secrets "apiToken" (default (randAlphaNum 40) $v) -}}
{{- $_ := set .Values "_wafcpAutoManaged" (append .Values._wafcpAutoManaged "WAF_CP_API_TOKEN") -}}
{{- end -}}
{{- if not .Values.secrets.bootstrapAdminPassword -}}
{{- $v := include "wafcp.lookupSecretKey" (dict "ns" $ns "name" $env "key" "WAF_CP_BOOTSTRAP_ADMIN_PASSWORD") -}}
{{- $_ := set .Values.secrets "bootstrapAdminPassword" (default (randAlphaNum 24) $v) -}}
{{- $_ := set .Values "_wafcpAutoManaged" (append .Values._wafcpAutoManaged "WAF_CP_BOOTSTRAP_ADMIN_PASSWORD") -}}
{{- end -}}
{{- end -}}
{{- if and .Values.postgres.bundled.enabled (not .Values.postgres.bundled.password) -}}
{{- if or .Values.secrets.existingSecret .Values.database.existingSecret -}}
{{- fail "postgres.bundled.password must be set explicitly when the database URL comes from your own Secret (secrets.existingSecret / database.existingSecret): it has to match that URL" -}}
{{- end -}}
{{- $v := include "wafcp.lookupSecretKey" (dict "ns" $ns "name" (include "wafcp.postgresAuthSecret" .) "key" "POSTGRES_PASSWORD") -}}
{{- $_ := set .Values.postgres.bundled "password" (default (randAlphaNum 32) $v) -}}
{{- $_ := set .Values "_wafcpAutoManaged" (append .Values._wafcpAutoManaged "POSTGRES_PASSWORD") -}}
{{- end -}}
{{- end -}}

{{/* The database URL when the chart owns it (bundled Postgres or database.url) */}}
{{- define "wafcp.databaseUrl" -}}
{{- if .Values.postgres.bundled.enabled -}}
{{- printf "postgres://%s:%s@%s:5432/%s" .Values.postgres.bundled.user .Values.postgres.bundled.password (include "wafcp.postgresFullname" .) .Values.postgres.bundled.database -}}
{{- else -}}
{{- .Values.database.url -}}
{{- end -}}
{{- end -}}
