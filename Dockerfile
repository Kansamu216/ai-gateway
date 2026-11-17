# =============================================================================
# workbuddy-nas —— 国内版 WorkBuddy 的 OpenAI 兼容网关 + 网页控制台
#
# 一个容器做两件事，刻意分成两个进程：
#   · console.mjs        管理面（8792）：登录、看额度、换凭据、发 Key
#   · workbuddy-bridge   数据面（8790）：给客户端调的 OpenAI 接口
# 控制台负责拉起/重启桥，桥挂了不影响管理页，反之亦然。
#
# 容器里没有 WorkBuddy 桌面客户端，拿不到 AtRest 解密密钥 —— 所以凭据有两条路：
#   1. 网页上传「已导出的明文 auth.json」（最省事，推荐）；
#   2. 网页里填一次 AtRest 密钥（export-auth.mjs --print-key），之后可直接上传
#      桌面端的加密 .info，由控制台解密。
# 桥对明文登录文件是原生支持的（openAuthField 遇字符串直接返回）。
# =============================================================================
# 基础镜像：优先用本地已有的标签。
# 这台 NAS 连不上 Docker Hub（已实测 registry-1.docker.io 超时），必须先通过
# 镜像源把它拉到本地。构建参数方便换源，不用改文件。
ARG NODE_IMAGE=node:22-alpine
FROM ${NODE_IMAGE}

WORKDIR /app

# 两个文件都是零依赖纯 Node 程序，不需要 npm install
COPY ai-gateway.mjs ./ai-gateway.mjs
COPY console.mjs ./console.mjs

ENV NODE_ENV=production \
    AIGW_BIND=0.0.0.0 \
    AIGW_PORT=8790 \
    AIGW_USAGE_FILE=/data/usage.jsonl \
    AIGW_CONSOLE_HOST=0.0.0.0 \
    AIGW_CONSOLE_PORT=8792 \
    AIGW_DATA_DIR=/data \
    TZ=Asia/Shanghai

RUN mkdir -p /data && chown -R node:node /data /app
USER node

EXPOSE 8790 8792

# 控制台的 / 页面不需要登录也能返回登录框，用它做健康检查最合适：
# 它同时证明「控制台在跑」和「Node 运行时正常」。
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.AIGW_CONSOLE_PORT||process.env.CONSOLE_PORT||8792)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# 入口是控制台：它自己 spawn 桥，并在桥异常退出时退避重启
CMD ["node", "console.mjs"]
