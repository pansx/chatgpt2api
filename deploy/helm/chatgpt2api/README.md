# 一键安装 chatgpt2api

要求 Kubernetes 集群、Helm 3，以及支持动态供给的默认 StorageClass。

    helm upgrade --install chatgpt2api ./deploy/helm/chatgpt2api --namespace chatgpt2api --create-namespace

默认自动生成并保存 API 密钥和内部 solver 密钥，自动设置 solver 地址；升级时保留已有密钥。
安装完成后按 Helm 提示读取密钥并用 port-forward 访问 http://localhost:8000。
需要自定义 API 密钥时加 --set-string authKey=你的密钥。

默认使用 pansx 的 sentinel-2026-10 镜像，单副本 API + 单副本 solver。
账号和 SQLite 数据保存在 10Gi PVC，Chromium 下载缓存保存在 2Gi PVC。
首次启动需要 root 权限安装系统依赖及联网下载 Chromium；启动探针最多等待 30 分钟。
主服务配置保存在数据卷内，升级和重启后保留。卸载会删除 PVC，请先备份账号数据。

需要出网代理时配置 proxy（主服务）、solver.proxy（浏览器）和 solver.downloadProxy（安装下载）。
例如：--set-string proxy=http://192.168.0.217:7073 --set-string solver.proxy=http://192.168.0.217:7073 --set-string solver.downloadProxy=http://192.168.0.217:7073
代理必须是集群可访问的地址，不应填客户无法访问的生产内网地址。

无 StorageClass 的临时测试可用 --set persistence.enabled=false，数据会随 Pod 删除而丢失。
通过 --set service.type=LoadBalancer 暴露服务；solver 始终仅提供 ClusterIP。

Compose 用户可直接运行仓库根目录的 `docker-compose.sentinel.yml`：

    CHATGPT2API_AUTH_KEY=your-key docker compose -f docker-compose.sentinel.yml up -d
