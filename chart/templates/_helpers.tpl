{{/* Expand the name of the chart. */}}
{{- define "theoros.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "theoros.fullname" -}}
{{- .Release.Name }}-{{ include "theoros.name" . }}
{{- end }}

{{/* Common labels */}}
{{- define "theoros.labels" -}}
app.kubernetes.io/name: {{ include "theoros.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Selector labels */}}
{{- define "theoros.selectorLabels" -}}
app.kubernetes.io/name: {{ include "theoros.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Create the name of the service account to use */}}
{{- define "theoros.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "theoros.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}