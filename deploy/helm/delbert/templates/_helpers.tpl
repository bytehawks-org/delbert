{{/* Base name of every object: the release name ("delbert" in the documentation). */}}
{{- define "delbert.fullname" -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}

{{- define "delbert.labels" -}}
app.kubernetes.io/name: delbert
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{/* Selector labels of one component: (dict "ctx" . "component" "core") */}}
{{- define "delbert.selector" -}}
app.kubernetes.io/name: delbert
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image of a Delbert component: (dict "ctx" . "component" "core") */}}
{{- define "delbert.image" -}}
{{- printf "%s/delbert-%s:%s" .ctx.Values.image.registry .component (.ctx.Values.image.tag | default .ctx.Chart.AppVersion) -}}
{{- end -}}

{{/* Name of the Secret with the generated passwords. */}}
{{- define "delbert.envSecret" -}}
{{- printf "%s-env" (include "delbert.fullname" .) -}}
{{- end -}}

{{/* Name of the Secret holding DATABASE_URL and DATABASE_MIGRATE_URL. */}}
{{- define "delbert.databaseSecret" -}}
{{- if and (not .Values.postgresql.enabled) .Values.externalDatabase.existingSecret -}}
{{- .Values.externalDatabase.existingSecret -}}
{{- else -}}
{{- include "delbert.envSecret" . -}}
{{- end -}}
{{- end -}}

{{- define "delbert.podSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
{{- end -}}
