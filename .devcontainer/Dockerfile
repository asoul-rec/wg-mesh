# wg-mesh devcontainer — Python 3.14 + WireGuard tools + Claude Code
FROM python:3.14-slim

ARG TZ
ENV TZ="$TZ"
ARG CLAUDE_CODE_VERSION=latest
ARG NODE_MAJOR=20
ARG GIT_DELTA_VERSION=0.18.2
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

# ---- Base development utilities ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ca-certificates \
        sudo \
        fish \
        fzf \
        jq \
        ripgrep \
        less \
        procps \
        man-db \
        unzip \
        gnupg2 \
        iproute2 \
        wireguard-tools \
        nftables \
        iputils-ping \
        dnsutils \
        nano \
        vim \
    && rm -rf /var/lib/apt/lists/*

# ---- Node.js (required for Claude Code) ----
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ---- GitHub CLI ----
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# ---- git-delta ----
RUN ARCH=$(dpkg --print-architecture) \
    && wget -q "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" \
    && dpkg -i "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" \
    && rm "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"

# ---- Non-root user with fish as login shell ----
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m -s /usr/bin/fish $USERNAME \
    && echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# ---- npm global dir owned by dev user ----
RUN mkdir -p /usr/local/share/npm-global \
    && chown -R $USERNAME:$USERNAME /usr/local/share/npm-global

# ---- Workspace + Claude config dir ----
RUN mkdir -p /workspace /home/$USERNAME/.claude \
    && chown -R $USERNAME:$USERNAME /workspace /home/$USERNAME/.claude

# ---- Persistent fish history (mount /commandhistory as a volume) ----
RUN mkdir -p /commandhistory \
    && chown -R $USERNAME:$USERNAME /commandhistory

ENV DEVCONTAINER=true
ENV SHELL=/usr/bin/fish
ENV EDITOR=nano
ENV VISUAL=nano
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
ENV PATH=/usr/local/share/npm-global/bin:/home/dev/.local/bin:$PATH

WORKDIR /workspace

# ---- Switch to non-root user ----
USER $USERNAME

# ---- uv (Python package manager) ----
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# ---- Fisher (fish plugin manager) ----
RUN fish -c "curl -sL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish \
        | source && fisher install jorgebucaran/fisher"

# ---- Fish config: activate venv, link history ----
RUN mkdir -p /home/$USERNAME/.config/fish /home/$USERNAME/.local/share/fish \
    && ln -sf /commandhistory/fish_history /home/$USERNAME/.local/share/fish/fish_history \
    && cat > /home/$USERNAME/.config/fish/config.fish <<'EOF'
# Activate the project venv if present (fish-native activator)
if test -f /workspace/.venv/bin/activate.fish
    source /workspace/.venv/bin/activate.fish
end

# fzf key bindings (if installed)
if test -f /usr/share/doc/fzf/examples/key-bindings.fish
    source /usr/share/doc/fzf/examples/key-bindings.fish
    fzf_key_bindings
end
EOF

# ---- Install Claude Code ----
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

CMD ["sleep", "infinity"]
