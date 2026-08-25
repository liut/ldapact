---
date: 2026-08-24
topic: ldapact-go-reimplementation
---

# ldapact Go 重写 — v1 范围与设计

## Summary

用 Go 重写 phpLDAPadmin 的日常管理员使用闭环，采用 Hybrid Spine 架构：核心骨架（LDAP 抽象、tree、HTTP 路由、会话、配置）Go-idiomatic 重写，模板层 v1 保留对 PHP `templates/*.xml` 的解析以兼容现有自定义模板，结构化日志从第一天埋点为 v2 审计打基础。

---

## Problem Frame

企业 IT 团队维护多年的 phpLDAPadmin 实例遭遇 **新部署环境无 PHP** 的问题（容器化、纯 Linux 基础镜像、Windows-only 服务器等场景），导致无法继续在 PHP 运行时上运行该工具。其他功能方面没有显著缺陷，因此目标是 **同等能力替换**，而非改进 LDAP 管理本身。

PHP 时代的若干设计遗产已不适合 Go 时代：file-cache、无长期进程内存、`_SESSION[APPCONFIG]` 全局、60+ 入口文件、XML 宏语言，但这些不能一刀切砍掉——生产中正在使用的自定义模板（很多企业根据自家 objectClass 扩展了 `templates/creation/*.xml`）必须保留到迁移完成。

---

## Actors

- **A1. LDAP 管理员**（终端用户）：日常维护目录的工程师，需要浏览树、查询、改条目、改密码、导入导出 LDIF、用模板建账号。
- **A2. LDAP 应用所有者**（间接用户）：拥有 LDAP 服务配置凭据的人，决定谁能登录、BaseDN、模板可见性。
- **A3. 运维/平台工程师**（部署者）：负责把 `ldapact` 单二进制部署到容器或裸机，配置 server profile。
- **A4. 未来审计员**（v2 受众）：通过 v1 起埋的结构化日志，事后追溯谁在何时改了什么。

---

## Key Flows

- **F1. 浏览目录子树**
  - **Trigger:** A1 登录后默认进入，或点击树节点。
  - **Actors:** A1
  - **Steps:** 根 BaseDN 加载 → 渲染根条目 → A1 点开某个 DN → 后端用分页 LDAP search 取该 DN 的直接子项 → 渲染子项列表
  - **States:** loading（占位行直到分页返回）、empty（无子项的 DN 显示"(no children)"静音行）、deep（面包屑显示祖先链，6 层以上中段省略号）、error（区分 size-limit-exceeded 与网络失败）。
  - **Outcome:** A1 看到 N 级子树，可继续展开。
  - **Covered by:** R1, R2, R18

- **F2. 创建 POSIX 账号（模板驱动）**
  - **Trigger:** A1 选中"Create user account"。
  - **Actors:** A1
  - **Steps:** 加载 `templates/creation/posixAccount.xml` → 解析 objectClass + attributes → 渲染多页表单（含 step indicator：当前页/总页数）→ A1 填写（uid、cn、uidNumber 自动获取、gidNumber 从 posixGroup 中 PickList、userPassword）→ 服务端逐页校验 + 最终提交 → 用模板 `<post>` 钩子把密码哈希成 R9 选定算法 → 用 LDAP add 创建条目
  - **States:** multi-page stateful navigation（返回保留已填值）、每页客户端校验钩子 + 服务端复核、R8.x/R8.y 失败 UX。
  - **Outcome:** 新条目存在于 LDAP，A1 看到成功页。
  - **Covered by:** R6, R7, R8, R8.x, R8.y, R9, R3

- **F3. 改用户密码**
  - **Trigger:** A1 在条目详情页点击"Change password"。
  - **Actors:** A1
  - **Steps:** 显示当前密码哈希算法（如 SSHA）→ A1 输入新密码两次（实时一致性校验）→ 服务端按 R9 算法哈希 + 检查 LDAP ppolicy overlay（如配置）→ LDAP modify 替换 userPassword
  - **Outcome:** 密码生效，下次绑定使用新密码；UI 显示行内"Password changed"banner 不重定向。
  - **Covered by:** R9, R3

- **F4. LDIF 导入**
  - **Trigger:** A1 选择"Import LDIF" 并上传 `.ldif`。
  - **Actors:** A1
  - **Steps:** 服务端解析 LDIF（顺序按文件流，应用 R11 大小/字符集限制）→ 逐条 LDAP add/modify → 失败条目收集到 `import-errors-<timestamp>.txt`（含 LDAP result code、行号、原始 LDIF chunk、修复建议）→ 成功条数+失败条数+失败明细内联展示给 A1 + 提供下载链接
  - **Outcome:** 成功条目已写入 LDAP；失败条目 A1 可下载错误报告修正后重试。
  - **Covered by:** R11

- **F5. 删除条目**
  - **Trigger:** A1 在条目详情页点击"Delete"。
  - **Actors:** A1
  - **Steps:** 渲染确认页（echo DN、RDN、子项数；非叶节点需输入确认文本）→ 提交 → 经 R15 写日志 → LDAP delete
  - **Outcome:** 条目从 LDAP 中移除；不可恢复（OpenLDAP 默认无 recycle bin）。
  - **Covered by:** R3, R15

- **F6. 重命名 / 移动条目**
  - **Trigger:** A1 在条目详情页点击"Rename / Move"。
  - **Actors:** A1
  - **Steps:** 模态框输入新 RDN（parent DN 只读）→ 提交 → LDAP modrdn → 刷新树视图以反映节点新位置
  - **Outcome:** 条目 DN 更新；树自动刷新到新位置。
  - **Covered by:** R3, R2

- **F7. 导出 LDIF**
  - **Trigger:** A1 在条目详情页或子树菜单点击"Export LDIF"。
  - **Actors:** A1
  - **Steps:** 选择范围（单条目 / 整子树）→ 提交 → 服务端按 RFC 2849 序列化，二进制属性 base64 → 下载 `.ldif` 文件
  - **Outcome:** A1 获得与导入兼容的 LDIF 文件。
  - **Covered by:** R10

- **F8. 搜索**
  - **Trigger:** A1 在顶部搜索框输入查询。
  - **Actors:** A1
  - **Steps:** 默认 scope = 当前选中节点子树，可切到全局（"recursive" 切换）→ 服务端按 R4 搜索 → 渲染结果表格（DN、objectClass 摘要、最后修改时间）→ 点击行进入条目详情
  - **Outcome:** A1 定位到目标条目。
  - **Covered by:** R4

---

## Requirements

### LDAP 与树

- R1. 支持 LDAP simple bind（含匿名 bind fallback）与 SASL bind；bind 凭据来自配置文件，应用启动时建立连接池，长连接复用。
- R2. 目录树按需加载：每个 DN 的直接子项在用户展开节点时才查询（paged search control），不预先建立整树缓存；查询 filter 默认 `(objectClass=*)`，可由配置覆盖。
- R3. 支持条目 add / modify / delete / rename（modrdn）；所有写操作走 LDAP modify 协议，不绕过服务端 schema 校验。
- R4. 搜索支持 base/one/sub scope、可配置 filter、属性选择、size limit、时间 limit；返回结果支持排序与分页。

### Schema 与模板

- R5. Schema 浏览只读：列出 objectClass（含 MUST/MAY 属性、structural/auxiliary 分类）和 attribute type（含 syntax、matching rule、单多值约束）；数据来自 LDAP subschema subentry（无独立 schema 文件）。
- R5.x. Schema 浏览的导航与详情：`objectClass` 列表点击进入详情页，展示 MUST/MAY 属性；`attribute type` 列表点击进入详情页，展示 syntax、matching rule、单/多值约束；从 objectClass 详情页的属性名可点击跳到 attribute 详情页。筛选/搜索 schema 项的 UX 推到 v2。
- R6. 模板驱动的条目创建，v1 内置 `inetOrgPerson`、`posixAccount`、`posixGroup` 三类；其他 objectClass 通过加载自定义 XML 模板支持。
- R7. XML 模板解析兼容 `~/Sites/phpLDAPadmin/templates/template.dtd` 的完整元素集合：`objectClasses`/`objectClass`、`attributes`/`attribute` 含 `id`/`display`/`icon`/`onchange`/`order`/`page`/`type`/`value`（含 `id` 多值 select）/`readonly`/`spacer`/`helper`/`post`/`verify`/`hidden`/`hint`/`default`/`cols`/`rows`/`size`/`maxlength`；顶层 `askcontainer`/`description`/`title`/`visible`/`rdn`/`regexp`/`noleaf`/`invalid`。
- R8. 实现模板宏函数 Go 等价（**两类**）：
  - **服务端宏**（在请求时由 Go 端求值）：`PickList`（8 位置参数，支持 fixed-value 注入和属性排序）、`GetNextNumber`（search/pool 双模式，pool 模式 filter 必须匹配至多一条；支持 `*2,+1000` 计算 token 和 startmin 下限；调用前以 server profile 的 `auto_number` 凭据独立 rebind）、`PasswordEncrypt`（调用 R9 哈希实现）、`PasswordEncryptionTypes`（列出可选算法）、`HashPassword`、`RandomPassword`、`Join`、`Default`、`DN`、`Encoded`、`Escape`、`Binary`、`HasMultiples`、`MultiList`。
  - **客户端宏**（编译为 per-attribute JS 片段，浏览器在 onchange 时运行）：`autoFill`（`target;template` 形式，模板支持 `%var|substart-end/modifier%` 子串/大小写/Unicode 标志）。
- R8.x. PickList 在 LDAP 搜索返回 0 候选时，渲染该字段为 free-text 输入并展示"未找到候选"提示，不阻塞提交。
- R8.y. GetNextNumber 达到配置上限时，渲染阻塞提示并允许管理员手动指定数值；两个失败 UX 都必须经 R15 写入日志。

### 密码与 LDIF

- R9. 密码修改支持算法集（按 `password_types()` 的 13 项减 Samba 推迟项）：`sha`、`ssha`、`md5`、`smd5`、`sha256`、`sha512`、`ssha256`、`ssha512`、`sha256crypt`、`sha512crypt`、`blowfish`、`crypt`、`ext_des`、`k5key`、`plain`、`md4`（AD userPassword，区别于 `sambaNTPassword`）。算法选择来自模板 `<post>` 钩子的参数；超出白名单的算法调用 `PasswordEncrypt` 时返回错误而非 fallback 到 PLAIN，避免静默明文存储。**不实现** `~/Sites/phpLDAPadmin/lib/createlm.php` 的 LM/`sambaNTPassword`/`sambaLMPassword`（v2 Samba）。
- R10. LDIF 导出支持条目级和子树级；遵循 RFC 2849 二进制属性 base64 编码。
- R11. LDIF 导入：按文件流顺序处理；遇到错误条目继续处理后续条目；最大 HTTP body 100MB（可配置）；最大条目数 100k；per-entry 属性数 sanity cap 1000；按 RFC 2849 严格校验 `dn:` 与属性值字符集；解析器使用 bounded buffer 流式处理。错误条目收集到 `.txt` 报告（每条目含 LDAP result code、行号范围、原始 LDIF chunk、服务器端修复建议），同时在导入结果页以表格内联展示摘要；报告文件名建议 `import-errors-<timestamp>.txt`。导出（条目级 / 子树级）遵循 RFC 2849 二进制属性 base64 编码。

### 服务器连接与配置

- R12. 单一 server profile 配置在 YAML 或 TOML 文件中（v1 不做多 profile 切换 UI），包含：`bind_dn`、`bind_password`、`auto_number_dn`、`auto_number_password`（独立凭据对，用于 GetNextNumber 服务端宏的独立 rebind）、`base_dn`、`tls`（min_version=TLSv1.2、verify=on、StartTLS=on、cert_expiry=fail_closed）、`schema_compat` 选项。`bind_password` 与 `auto_number_password` 由同一 secret resolver 链解析：env var（如 `LDAPADM_BIND_PASSWORD`）→ 文件引用（mode 0600 校验失败时拒绝启动）→ TTY 提示（容器/服务场景由 systemd `LoadCredential` 或 k8s `Secret` 注入文件）。明文 YAML 字段、`process env`（`/proc/PID/environ` 暴露）、CLI flag 均不被接受。
- R13. 会话用 cookie + 服务端 store（具体存储选型由 ce-plan 决定），无 PHP 风格 session 文件；登录后 cookie 设置 `HttpOnly` + `Secure`（生产配置下）+ `SameSite=Strict`；会话超时（默认 30 分钟，可由 server profile `session_timeout_min` 字段覆盖）后服务端清理对应 store 条目；server profile 另含 `session_expired_action` 字段（取值 `redirect_to_login` 或 `retry_bind`，默认 `retry_bind`）控制会话失效后的客户端行为。每次成功 bind（或任何权限提升事件）必须 invalidate 旧 session ID 并签发新 ID（防 session fixation）。

### 架构、日志与可演进性

- R14. Hybrid Spine：核心（LDAP 抽象、tree、路由、会话、配置）Go-idiomatic；模板层 v1 保留对 PHP 风格 XML 模板格式的解析；具体解析实现由 ce-plan 决定（stdlib XML、第三方库、或自研）。模板按需惰性解析（首次使用时解析），不预编译到启动期缓存。模板解析对 LDAP subschema 有依赖（`templates/template.dtd` 中属性名需对 LDAP subschema canonicalise），故启动期如果 LDAP 不可达，进程 fail-fast 退出并写 stderr 报错（不缓存空 schema）。
- R15. 所有 LDAP 写操作通过 slog 结构化记录：事件名（`ldap.create` / `ldap.modify` / `ldap.delete` / `ldap.rename`）、actor、目标 DN、操作类型、时间戳。日志格式 JSON，可由 `LDAPADM_LOG_LEVEL` 环境变量切换 level；为 v2 审计产品化（日志聚合、查询 UI）保留接口。**`userPassword` 的任何值（哈希前/后）严禁出现在任何日志字段**——diff writer 必须按属性名 redact；属性名本身可记，值不记。多值属性的 diff 在 v1 中不展开（v2 审计产品形态确定后细化）；当前 v1 仅记录操作类型与目标 DN，不记录 before/after。
- R16. `ServerProfile` 在 v1 中以 struct 形式承载配置（字段见 R12）。v2 引入多 profile 时再抽象为 interface 并扩展实现（Go 的结构化类型让该重构机械）。
- R17. 交付物：单一 Go 二进制 + 嵌入的 Web 资源（HTML/CSS/JS）+ 可选配置文件；不依赖 PHP runtime、PHP-FPM、Apache。
- R18. Web UI 目标 WCAG 2.1 AA：键盘可达（Tab/Shift+Tab 顺序），tree 浏览器暴露 `role=tree` / `aria-expanded` / `aria-level`，焦点可见，SR 公告展开/折叠含子项数；触摸目标最小 24×24px。

---

## Acceptance Examples

- AE1. **Covers R1, R17.** Given `ldapact` 启动时 server profile 的 bind DN/密码正确, when A1 访问根路径, then 自动以该 bind DN 登录（A1 不需要单独登录页），并看到根 BaseDN 树，且进程是单一 Go 二进制无 PHP 依赖。
- AE2. **Covers R2.** Given 根 DN 有 5000 个直接子项, when A1 展开根节点, then 服务端用 paged search（每页 1000）分 5 次取回子项，渲染只展示第一页并提供"加载更多"，且服务端不缓存这 5000 条到内存。
- AE3. **Covers R6, R7, R8.** Given `~/Sites/phpLDAPadmin/templates/creation/posixAccount.xml` 存在于自定义目录, when A1 选择创建 posixAccount 模板, then Go 端解析该 XML 渲染出与 PHP 版本一致的表单（含 cn、uid 自动联动、uidNumber 自动取下一个空闲值、gidNumber 从 posixGroup 下拉选择），提交后服务端用模板 `<post>` 钩子的 `PasswordEncrypt` 把密码哈希成 SSHA 后 LDAP add 成功。
- AE4. **Covers R9.** Given userPassword 当前为 SSHA, when A1 在条目详情页修改密码为 `NewPass#2026`, then 服务端用 SSHA 算法哈希后 modify 替换，LDAP bind 用新密码成功，旧密码失败。
- AE5. **Covers R11.** Given 上传的 LDIF 中第 12 条条目因违反 schema 失败, when 服务端处理, then 该条失败被记录到错误报告（含行号 12、失败原因、对应 LDIF 文本），第 13 条及之后的条目继续处理；导入结束后 A1 看到"成功 N 条，失败 M 条"以及下载错误报告的链接。
- AE6. **Covers R15.** Given A1 通过模板创建了一个新用户, when LDAP add 成功返回, then slog 输出 JSON 行包含 `event=ldap.create`、`actor=<bind DN>`、`dn=<新条目 DN>`、`op_type=add`（modify/delete/rename 同理）；该日志行**不包含任何 userPassword 值**（包括哈希前/后）；可用 `LDAPADM_LOG_LEVEL=info` 在 stdout 看到，可用 `LDAPADM_LOG_LEVEL=error` 屏蔽。
- AE7. **Covers R13.** Given A1 登录后获得 session cookie, when 30 分钟内无操作, then cookie 自动失效且服务端清理 session store 条目（A1 下次请求被重定向到登录页或 bind 重试，行为由 server profile 配置决定）。

---

## Success Criteria

- **人类结果：** 企业 IT 团队可在新部署环境（无 PHP）中运行 `ldapact` 实现与 phpLDAPadmin 1.2.5 等同的日常 LDAP 管理能力，且切换日 0 停机、0 数据回退。
- **下游移交质量：** ce-plan 能从本文件直接列出代码模块切分、依赖选择、测试策略，不需要回头问产品行为；ce-work 可在不重新讨论范围的前提下完成 v1 实现。
- **可演进性验证：** v2 引入 Samba NT/LM 哈希、批量操作、多 server profile 时，需求变更只发生在 `~/Sites/phpLDAPadmin` 对应的"扩展点"，不要求重写 R14 描述的核心骨架。

---

## Scope Boundaries

**v1 范围内（包含上述 Requirements 所有项）。**

**Deferred for later（明确推后）：**
- Samba 模板（sambaSamAccount / sambaGroupMapping 等）与 NT/LM 哈希生成
- 批量操作（mass_edit / mass_update）
- 多 server profile 切换 UI
- 审计日志产品化（查询界面、保留策略、导出报表）
- SSO 集成（OIDC / SAML 登录替代 LDAP bind）
- 国际化框架（i18n 资源加载、运行时切换语言）
- 自助密码重置门户（终端用户改自己密码的流程）
- 自定义 schema 加载/扩展工具
- LDAP 监控/复制/同步相关工具
- CLI / TUI 模式
- gRPC / 嵌入式 LDAP 代理

**Outside this product's identity（不属于本产品）：**
- 通用 LDAP 客户端库（应作为依赖而非本项目核心）
- LDAP 服务端实现
- 用户自助服务门户（不属于"管理员工具"语义）

---

## Key Decisions

- **采用 Hybrid Spine 而非 Clean Room Go 重写**：v1 承担 XML 模板解析开销，换取现有自定义模板零迁移成本；v2 再考虑切到 YAML/Go 结构体模板。**前提**：该决策需要 Resolve Before Planning 中"v1 上线前生产 custom 模板 inventory"完成，确认实际有非零数量自定义模板需要兼容。
- **v1 单服务器配置**：`ServerProfile` 以 struct 承载（不抽象为 interface）；v2 引入多 profile 时再抽象为 interface 并新增实现——Go 的结构化类型让该重构机械。
- **Schema 浏览只读**：v1 不做 schema 扩展/加载 UI；写 schema 通过手工 LDIF 导入。理由：完整替代目标下，schema 管理在生产中极少使用，把投入放到更常用的功能上。Schema 浏览包含 navigation/detail（R5.x）；筛选/搜索 UX 推到 v2。
- **不用 PHP session 文件**：Go 进程常驻，会话直接走 cookie + 服务端 store（BoltDB 或内存 map），避免 PHP-FPM 风格的"无状态共享文件系统"模式。每次成功 bind 必须轮换 session ID（防 session fixation）。
- **结构化日志从第一天埋点**：v1 slog 输出 JSON 但**仅记录事件名/actor/dn/op_type，不记录 before/after 属性 diff**（v1 无审计消费者，记 diff 是 YAGNI；v2 审计产品确定形态后再补 diff）。`userPassword` 任何值永久 redact。
- **不实现 NT/LM 哈希**：v1 期间 Samba 账户走 LDIF 手工维护；NT/LM 哈希逻辑（`lib/createlm.php` + `lib/blowfish.php` 480 行）推迟到 v2 与 Samba 模板一起做，避免 v1 引入未使用代码。
- **Web UI 不重做 SPA**：v1 用 SSR HTML + 轻量 JS（具体技术栈在 Outstanding Questions 中待 ce-plan 决定 HTMX vs 原生 fetch），不引入 React/Vue；理由：管理员工具对 UI 流畅度不敏感，避免前端构建链引入复杂度。WCAG 2.1 AA 强制要求（R18）。
- **绑定凭据安全基线**：bind password 必须经 secret resolver（env var / 0600 文件 / TTY 提示）解析；不接受 YAML 明文、process env、CLI flag。auto_number 凭据独立但使用相同 resolver。
- **认证模型：v1 采用 admin DN 单一 bind + 服务端 session**（即现有 AE1 模型）；不引入 per-user bind。**前提**：Resolve Before Planning 中"v1 部署模型"确认（loopback-only / 内部 VPN / mTLS-fronted / 公网暴露）；若需要公网暴露则改为 per-user bind，重写 R1/R13/AE1。

---

## Dependencies / Assumptions

- **依赖 LDAP 库**：候选 `go-ldap/ldap/v3` 或 `nmcclain/ldap`；最终选择由 ce-plan 决定。
- **依赖 HTTP 路由**：stdlib `net/http` + `http.ServeMux`（Go 1.22+）或 `chi`；同上由 ce-plan 决定。
- **假设 go-ldap 支持 Paged Results Control**：本设计的 R2 依赖此能力；如不支持，需要客户端自行实现 simple paging。
- **假设 LDAP server 支持 subschema subentry**（RFC 4512）：R5 依赖此能力；OpenLDAP、389 DS、AD 全部支持。
- **假设目标 LDAP server 至少支持 LDAPv3**：R1 隐含。
- **假设生产 LDAP 部署为 `auto_number.dn/auto_number.pass` 提供独立凭据对**：R8 GetNextNumber 服务端宏要求；R12 把这两个字段加入 server profile；如果实际部署无独立 auto_number 凭据，运维需要在 LDAP 中创建对应账户（或在配置中复用 bind DN）。
- **未验证**：现有生产 phpLDAPadmin 实例中实际使用了 `htdocs/` 下哪些 PHP 文件（除 R6/R9/R11 明确涉及的外），参见 Outstanding Questions 中的"smoke test"项。

---

## Outstanding Questions

### Resolve Before Planning

- **[Affects C1][User decision]** v1 部署模型（决定认证形态）：ldapact 是否仅在 loopback / 内部 VPN / mTLS-fronted / 单租户内网暴露？若是，单一 bind + 服务端 session 模型（当前 AE1/R13）可接受。若需公网/多租户暴露，必须改为 per-user bind，重写 R1/R13/AE1/Security Key Decision。**当前决策**：假设前一种部署模型；若实际部署场景与假设冲突，本节需要回头修改。
- **[Affects C2][User decision]** 日常 admin loop 闭合定义：Success Criterion 1 说"等同于 phpLDAPadmin 1.2.5 日常能力"，但 v1 R3/R4/R5/R10 全部声明 v1 范围，F1-F8 现在已覆盖 browse/create/password/import/delete/rename/export/search。**确认**：F1-F8 = "daily admin loop closed"，所有其他 R 项的 Capability 都已被某条 flow 触达。若发现遗漏项，本节需补 flow。
- **[Affects C3][User decision]** Hybrid Spine XML 前提：先做生产 inventory（grep 自定义模板目录 `=php.` 引用并统计 unique 函数集合；统计 templates/*.xml 文件总数）确认实际有非零数量自定义模板需要兼容，再决定是否坚持 XML 兼容或切到 YAML/Go 结构体模板（+写 XML→YAML 一次性迁移脚本）。**当前决策**：坚持 Hybrid Spine，inventory 完成后回看。
- **[Affects C4][User decision]** "0 停机、0 数据回退" success criterion：当前无任何 v1 Requirement 支持该断言。要么 (a) 软化为可测形式（如"切换后 30 天内无生产事故"），要么 (b) 在 R 系新增"迁移工具"requirement（dual-run mode、URL 兼容 shim、PHP→YAML 配置转换、模板 parser 回归 corpus）。**当前决策**：默认 (a)，如切 (b) 需要补 R 系列。
- **[Affects 完整替代定位][User decision]** "完整替代" framing 与 9 项 Deferred 矛盾：Samba 模板/批量/多 server/审计/SSO/i18n/自助密码/自定义 schema/CLI 全部推迟。如部署目标实际有非平凡 Samba 或批量需求，必须重新评估 v1 范围。建议先调研目标部署的实际生产 phpLDAPadmin 使用数据（grep 模板、读运维对话）作为 v1 范围锁定依据。
- **[Affects Adjacent positioning][User decision]** Apache Directory Studio / lldap / GLAuth 等成熟替代工具的存在：v1"完整替代"在企业 IT 现场会被这些工具挑战。是否需要在 v1 中显式做差异化（如"单机单二进制零依赖"对比 ApacheDS 的 Java 依赖）？
- **[Affects CSRF 策略][User decision]** state-changing endpoints（F2/F3/F4/F5/F6）的 CSRF 防护策略：SameSite=Strict only / token-based / Origin header / 多重防御。
- **[Affects 密码策略 floor][User decision]** R9 哈希算法 floor 与明文策略：PLAIN 是否完全拒绝 / 旧算法（MD5/SHA-1）仅作 read-side 译码器而禁止 write-side / 升级 SSHA-512 / ARGON2id 时机。
- **[Affects 密码复杂度][User decision]** 密码最小长度/复杂度/历史/breach dictionary 检查的执行方：LDAP ppolicy overlay / 应用层 / 两者并存。
- **[Affects R12 凭据强化][User decision]** secret resolver 链是否对全部场景充分（env / 0600 文件 / TTY）？是否需要支持 Vault/AWS Secrets Manager/k8s Secret 适配器（v1 推迟到 v2）？
- **[Affects R7 XML 安全][User decision]** 自定义 XML 模板加载策略：是否仅接受 server-profile 指定目录的可信模板，还是允许运行时上传/拉取新模板（后者需模板签名机制）？PickList/GetNextNumber 的 LDAP 查询范围是否限制在 server profile 的 base DN 子树内（防 SSRF）？
- **[Affects A2 角色][User decision]** A2 "LDAP 应用所有者" 角色是否保留为正式 Actor？若保留需要增加 flow（模板可见性配置、bind 凭据轮换、BaseDN 修改）；若删除则合并到部署/运维文档。
- **[Affects A4 角色][User decision]** A4 "未来审计员" 是否保留为正式 Actor？若保留则明示 v2 范围；若删除则 R15 的目标受众改为"运维/合规导出"。
- **[Affects R9 NTLM 精确描述][User decision]** R9 中 "AD (NTLM)" 与 Key Decisions "NT/LM 推迟 v2" 互相对抗：AD userPassword（MD4(UTF-16LE)）与 `sambaNTPassword` 是不同字段但同算法。文档需明确区分两者。
- **[Affects Web UI 技术栈][User decision]** HTMX vs 原生 fetch + JS fragment：当前 Key Decision 留待 ce-plan 决定。是否锁到 HTMX（更简洁的服务端 fragment 渲染范式）以减少 ce-plan 决策开销？
- **[Affects R15 actor 字段][User decision]** v1 单一 bind 模型下，actor 字段语义是"bind DN"还是"session 标识"还是两者并列？v1 AE6 已用 bind DN，需统一到 R15 body。
- **[Affects 审计完整性][User decision]** R15 在 v1 是否要求 append-only 输出（chattr +a / syslog）+ HMAC 链（防篡改）？
- **[Affects v1 模板 macro 完整集][User decision]** 在 C3 inventory 完成后，根据 grep 结果决定 R8 的 13+ macro 完整集是否全部 v1 实现；v1 仅实现核心 4 个 vs v1 实现全部 13+ 个对 v1 时间表影响显著。
- **[Affects XML parser 回归][User decision]** parser 回归 corpus 来源：从生产 phpLDAPadmin 抽取 templates/*.xml 作为 fixture 集 vs 仅用 phpLDAPadmin 内置 3 个 vs 第三方语料库。
- **[Affects R1 SASL 范围][User decision]** SASL bind 是 v1 必须还是推迟到 v2？若必须，GSSAPI / SCRAM-SHA-256 优先级。
- **[Affects R1 TLS 强制][User decision]** v1 是否允许 plaintext LDAP 连接（开发环境）？强制 StartTLS / LDAPS 的最小 TLS 版本（1.2 / 1.3）？
- **[Affects R1 限流][User decision]** web 层 bind 失败限流策略：per-IP / per-bind-DN / 两者；ppolicy lockout 响应如何表面化？
- **[Affects 安全响应头][User decision]** v1 默认响应头集合：CSP / X-Frame-Options / HSTS / Referrer-Policy / X-Content-Type-Options 的具体配置。

### Deferred to Planning

- **[Affects R1][Technical]** LDAP 客户端库选择（`go-ldap/ldap/v3` vs `nmcclain/ldap`）以及连接池实现细节。
- **[Affects R2][Technical]** 树浏览的分页大小默认值（建议 100）与"加载更多"交互的具体 UX。
- **[Affects R5][Technical]** Schema 浏览页面筛选/搜索 UX（v2 项）。
- **[Affects R8][Technical]** 服务端宏的具体 Go 函数签名与并发模型；客户端 macro（autoFill）编译为 JS 片段的机制。
- **[Affects R8.x/R8.y][Technical]** PickList 失败自由文本输入的具体 UX；GetNextNumber 配置上限（hard ceiling）的来源（模板定义 vs server profile 全局）。
- **[Affects R9][Technical]** AD NTLM 哈希的 Go 实现选择（重新实现 vs 调用 cgo 绑定系统库）。
- **[Affects R12][Technical]** 0600 文件模式校验在不同 OS（Windows / 容器 rootless / SELinux）下的差异处理。
- **[Affects R13][Technical]** Session store 选型：BoltDB 文件 vs 内存 map（重启清空）vs Redis；具体 store 选型影响运维而非功能。
- **[Affects R15][Technical]** slog 输出位置（stdout/stderr/syslog 文件）默认行为与生产配置切换；userPassword redaction 的具体实现（attribute name filter vs sink-level hook）。
- **[Affects R15 性能][Technical]** R15 不记 diff 之后，是否需要在 actor/dn 之外记录"操作前后的 entry size 差"作为轻量级审计信号？
- **[Affects R17][Technical]** 嵌入 Web 资源的打包方式（go:embed / 独立 static dir）。
- **[Affects F1][Technical]** 多级 tree 的"加载更多"具体 UX：按需加载（每次点开 fetch）vs 虚拟滚动（只渲染视口内行）vs 完整 paged search。
- **[Affects web UI][Technical]** HTMX vs 模板原生 JS vs 其他；具体 UI 框架由 ce-plan 在看到 R 之后决定。
- **[Affects migration][Needs research]** v2 模板从 XML 切到 YAML 时，是否需要写迁移脚本；如果企业有数百个自定义 XML 模板，迁移成本是非平凡的。
- **[Affects R1 凭据内存][Technical]** bind credential 在 Go 进程内存中的存储卫生：mlock、GOTRACEBACK 配置、core dump 行为。
- **[Affects R16 v2][Technical]** 多 profile 时 per-profile trust boundary 实现细节；profile 切换 UI 与 audit log profile 字段。
