{{/* SPDX-License-Identifier: BUSL-1.1 */}}

{{- define "waf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waf.fullname" -}}
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

{{- define "waf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "waf.labels" -}}
helm.sh/chart: {{ include "waf.chart" . }}
{{ include "waf.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: data-plane
{{- end -}}

{{- define "waf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "waf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "waf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "waf.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image refs — tag defaults to the chart appVersion */}}
{{- define "waf.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "waf.agentImage" -}}
{{- $tag := .Values.agent.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.agent.image.repository $tag -}}
{{- end -}}

{{/* True when the managed CRS file is in play (agent maintains it) */}}
{{- define "waf.managedRulesEnabled" -}}
{{- if or .Values.agent.enabled .Values.waf.managedRules.enabled -}}true{{- else -}}false{{- end -}}
{{- end -}}
