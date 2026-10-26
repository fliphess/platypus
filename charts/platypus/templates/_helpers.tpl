{{/* Name of the chart, overridable. */}}
{{- define "platypus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Full name: the release name, unless it already contains the chart name. */}}
{{- define "platypus.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Labels on every object. */}}
{{- define "platypus.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "platypus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels of one component (web or worker). Call with (dict "root" $ "component" "web"). */}}
{{- define "platypus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "platypus.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "platypus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "platypus.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "platypus.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}
{{- end }}

{{/* Name of the Secret holding the secret settings. */}}
{{- define "platypus.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- include "platypus.fullname" . }}
{{- end }}
{{- end }}

{{/*
  Pod spec shared by web and worker. Call with
  (dict "root" $ "component" "web" "command" "web" "values" .Values.web).
*/}}
{{- define "platypus.podSpec" -}}
{{- $root := .root }}
serviceAccountName: {{ include "platypus.serviceAccountName" $root }}
automountServiceAccountToken: false
{{- with $root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
securityContext:
  {{- toYaml $root.Values.podSecurityContext | nindent 2 }}
containers:
  - name: {{ .component }}
    image: {{ include "platypus.image" $root }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args: [{{ .command | quote }}]
    securityContext:
      {{- toYaml $root.Values.securityContext | nindent 6 }}
    ports:
      {{- if eq .component "web" }}
      - name: http
        containerPort: 8080
        protocol: TCP
      {{- end }}
      - name: health
        containerPort: 8081
        protocol: TCP
    envFrom:
      - configMapRef:
          name: {{ include "platypus.fullname" $root }}
      - secretRef:
          name: {{ include "platypus.secretName" $root }}
    {{- with $root.Values.databaseCA.configMap }}
    env:
      - name: PLATYPUS_DB_SSLROOTCERT
        value: /etc/platypus/database-ca/{{ $root.Values.databaseCA.key }}
    {{- end }}
    # A slow first start (database not reachable yet) must not be restarted:
    # the startup probe gives it up to five minutes, then liveness takes over.
    startupProbe:
      httpGet:
        path: /healthz
        port: health
      periodSeconds: 5
      timeoutSeconds: 2
      failureThreshold: 60
    livenessProbe:
      httpGet:
        path: /healthz
        port: health
      periodSeconds: 10
      timeoutSeconds: 2
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /readyz
        port: health
      periodSeconds: 10
      timeoutSeconds: 3
      failureThreshold: 2
    resources:
      {{- toYaml .values.resources | nindent 6 }}
    volumeMounts:
      - name: tmp
        mountPath: /tmp
      {{- if $root.Values.databaseCA.configMap }}
      - name: database-ca
        mountPath: /etc/platypus/database-ca
        readOnly: true
      {{- end }}
volumes:
  - name: tmp
    emptyDir: {}
  {{- with $root.Values.databaseCA.configMap }}
  - name: database-ca
    configMap:
      name: {{ . }}
  {{- end }}
{{- with .values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .values.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
