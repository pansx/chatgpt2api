{{- define "c.name" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 54 | trimSuffix "-" -}}
{{- end -}}
