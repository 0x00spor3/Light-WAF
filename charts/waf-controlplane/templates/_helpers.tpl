{{/* SPDX-License-Identifier: BUSL-1.1 */}}

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

{{/* The database URL when the chart owns it (bundled Postgres or database.url) */}}
{{- define "wafcp.databaseUrl" -}}
{{- if .Values.postgres.bundled.enabled -}}
{{- printf "postgres://%s:%s@%s:5432/%s" .Values.postgres.bundled.user .Values.postgres.bundled.password (include "wafcp.postgresFullname" .) .Values.postgres.bundled.database -}}
{{- else -}}
{{- .Values.database.url -}}
{{- end -}}
{{- end -}}
