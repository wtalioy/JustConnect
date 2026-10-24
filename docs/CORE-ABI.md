# JustConnect 内部 C ABI v1

公共入口为 [justconnect.h](../corelib/abi/justconnect.h)，Go 实现在同一 `corelib/` 模块的 `abi/` 与 `internal/bridge/`。S1-03 提供契约和传输；S1-07 已接入正式 aTrust 会话，S1-08 的 `EmbeddedCoreEngine` 通过专属 Qt 工作线程调用本接口。

## 单一契约来源

[contract.json](../corelib/abi/contract.json) 集中定义版本、状态码、安全上限及上游基线。运行 `python scripts/generate-core-abi.py` 生成 `constants.h` 与 `internal/bridge/constants.go`；`--check` 只核对差异，普通三平台与六组 FFI CI 均执行。生成文件不手改；字段结构在 Go 类型中定义，本文件记录宿主语义。

构建提交与工作树状态由 Git 查询注入，不填写开发机目录、学校地址或账户。`jc_build_info` 返回当前 Go 版本、目标 OS／架构、JustConnect 完整提交、上游基线和由提交／工作树状态组成的本地版本。直接手动构建而没有 VCS 信息时明确返回 `unversioned/unknown`，不能作为可追溯发布产物。

正式库返回 `embedded_vpn:true`、`auth_method_query:true`、`authentication_cache:true`、`policy_update:true`、`initial_protection:true`、`name_protection:true`、`network_snapshot:true`、`resource_snapshot:true`。Start 使用真实会话：认证、资源、选线、IP 握手、解析、gVisor 和监听均成功后才产生 `ready`，失败或取消在清理完成后产生终态。该事件仅表示核心通道／本地代理就绪；系统接管与系统 DNS 不在其契约内，产品“已连接”须由应用层按 [R11／S7-02](../plan.md) 汇总完整就绪条件。只有测试驱动和未安装 Runner 的纯传输引擎没有 VPN 能力；测试驱动始终标记 `test_driver:true`。

`capabilities.tunnel_mtu` 返回当前核心校园 L3 栈的 MTU，直接来自栈实现；测试驱动返回 0。需要配置原始 IPv4 TUN 的调用方先核对 `raw_ipv4_tun_fd`，再使用该值准备设备，不在宿主复制核心默认值。它不替代内核 MTU 回读或设备接收校验，也不表示其他平台已支持原始 fd。

## C 边界与生命周期

仅使用固定宽度整数和有长度的字节缓冲区；句柄是单调递增、从不重用的整数，不是地址。没有跨边界对象、异常、字符串指针返回值、分配／释放配对或 Go 回调 Qt。

UTF-8 JSON 不带结尾 NUL。输入仅借用至调用返回，库在返回前完成复制和解析；宿主随后可覆盖或释放配置／认证回应。输出及标量结果由宿主分配，内存必须有效且互不重叠。库检查空指针、长度、容量和超限，不探测任意非空地址是否可访问。Go 不保留 C 缓冲区，也不返回 Go 内存。

`length/handle/generation` 输出在错误时归零，`JC_BUFFER_TOO_SMALL` 则返回所需长度。容量不足不写任何字节、不消费事件；可用空指针／零容量查询长度，再扩容读取同一事件。成功输出不补 NUL。

| 函数 | 行为 |
| --- | --- |
| `jc_abi_version()` | 返回 ABI 版本 |
| `jc_build_info(abi, output, capacity, length)` | 校验版本，返回构建来源和实际能力 JSON |
| `jc_network_snapshot(abi, output, capacity, length)` | 只读返回当前接口／IP 路由及观察时间，不创建会话或改网络 |
| `jc_config_validate(abi, config, length)` | 使用启动时同一解析器作纯配置校验，不创建会话、不监听或联网；同样限制输入长度／未知字段 |
| `jc_session_create(abi, handle)` | 校验版本，创建空闲句柄；保留数量受契约限制 |
| `jc_session_start(handle, config, length, generation)` | 同步严格校验并复制配置，异步启动；返回代次 |
| `jc_session_read(handle, wait_ms, output, capacity, length)` | 有界等待一个 FIFO 事件；容量不足可重试 |
| `jc_session_respond(handle, response, length)` | 仅接受匹配、已读取且尚未消费的认证请求 |
| `jc_session_update_policy(handle, policy, length, generation)` | 完整校验后原子替换本代保护规则，成功返回生效代次，失败输出零 |
| `jc_session_resources(handle, generation, output, capacity, length)` | 只读返回本代实际解析的校园资源，未就绪时返回 Busy，旧代次或停止后拒绝 |
| `jc_session_attach_tun(handle, generation, fd, mtu)` | Linux 就绪代次接收经助手验证的非阻塞原始 IPv4 TUN fd；仅成功后持有自身副本，停止前释放 |
| `jc_session_attach_tun_dns(handle, generation, fd, mtu)` | 同一 fd 接收契约，启用校园 DNS 应答前的所属路由发布确认 |
| `jc_session_ack_dns_routes(handle, generation, request_id, applied)` | 仅确认已读取的同代次 `dns_routes` 请求；`applied` 严格为 0／1 |
| `jc_session_stop(handle, wait_ms)` | 先取消，再有界等待清理；重复停止有效句柄成功 |
| `jc_session_destroy(handle, wait_ms)` | 清理完成后失效、释放句柄；重复销毁已签发句柄成功 |

进程内只允许一个活动会话；其他 Start 返回 `JC_BUSY`。清理完成前不释放活动名额。等待超时返回 `JC_TIMEOUT`，可重试；未清理完的句柄不能重启。销毁请求从发起起即禁止该句柄重新启动。

每次成功 Start 增加代次，事件序列从 1 开始；前一代未读事件必须读完才能重启。Stop 保留认证和终态事件，唤醒阻塞读取。Destroy 成功后显式丢弃剩余事件，使借用会话的读取失效。结束且无剩余事件返回 `JC_END`；空闲等待到期返回 `JC_TIMEOUT`；正在停止且终态尚未入队时可返回 `JC_CANCELLED`，随后仍可读取终态。

导出可并发调用，不持有全局句柄锁等待网络、认证或宿主读取。`wait_ms` 不得超过契约上限。状态码没有自由格式错误文本；终态消息只由安全状态生成，不回传解析器原文、服务端响应或 panic 内容。

## JSON 配置

ABI v1 与 JSON schema 版本同步。S2-02 以兼容增补导出 `jc_config_validate`，不改变既有签名与 JSON 结构；应用同时检查版本和所需符号，缺失时明确报告核心不可用。示例为隔离测试地址，运行配置由宿主提供：

~~~json
{
  "schema_version": 1,
  "operation": "connect",
  "server": {"host": "vpn.example.invalid", "port": 443},
  "auth": {"method": "auth/psw", "username": "example-user", "password": "example-secret"},
  "listeners": {"socks": "127.0.0.1:1080", "http": "[::1]:1081"},
  "network": {"auto_detect": false, "language": "en-US"}
}
~~~

`schema_version/server.host/server.port` 必填。host 是 ASCII DNS 名或 IP，不是 URL／带端口地址，端口显式指定。其他字段可省略；`auth` 还接受 `phone/domain/totp_secret/auth_id/sub_type`，method 支持空值（按用户名／密码或手机号推导）、`auth/psw`、`auth/smsCheckCode`、`auth/cas`、`auth/httpsOauth2`。listener 空值不启用；非空必须是回环 IP:port。没有 CLI 附加参数、默认学校、TUN、路由／DNS 修改或原始调试输出开关。

核对 `initial_protection` 能力后，connect 配置可附 `protection:{protected:[规范前缀],campus:[IPv4 地址]}`；两数组必填，使用与实时更新相同的完整校验。Start 在启动协议 Runner、保活和代理监听之前原子安装不可变规则，初始修订为 0，之后更新从 1 递增。无效配置不创建连接或消耗代次，省略字段维持原契约；每次新会话重新取本次配置，auth_methods 拒绝此字段。Qt 适配器在每次 connect（含重连）的工作线程中读取原网络与系统 DNS 快照，复用应用范围／名称推导并生成完整初始配置；同时核对 name_protection，默认不含校园例外。缺少能力、读取／推导失败或超限时不启动会话，取消会在读取返回后再次检查；auth_methods 不读保护快照。Qt 当前自动安装地址及名称保护，并通过应用协调及查看窗口接入明确 IPv4 选择／撤回；网络变化自动更新仍待接入，不代表系统接管已就绪。

`operation` 缺省为 `connect`；`auth_methods` 只查询认证方式，产生 `auth_methods` 结果（`methods:[{type,domain,name,login_url,auth_id,sub_type}]`）及终态，不建立数据栈或代理。结果数量、字段和整体事件大小均有界，超限返回 `JC_LIMIT`。

`network` 支持 `interface/auto_detect/local_dns/secondary_dns/dns_cache_ttl/disable_remote_dns/language`。接口、DNS 和语言显式传入；local DNS 允许 IP 或 IP:port，secondary DNS 为 IP。接口名优先于自动选择；自动选择默认关闭，避免悄悄改变宿主的网络策略。DNS 缓存寿命与维护间隔的默认值集中在 `corelib/session.go`，缓存不启动游离 janitor，且有容量上限。代理出口不读取系统 HTTP_PROXY 等环境配置；本阶段不修改路由、系统代理或系统 DNS，不创建自己的 TUN。Clash 共存仍由后续阶段验证。

拒绝重复键、未知字段、非规范字段大小写、尾随 JSON、null、超深结构、无效 UTF-8、NUL 和 Unicode 替代字符。超限值不截断、不静默回退。无效输入只返回 `JC_INVALID_ARGUMENT`，不把账户、密码或输入片段写入错误。

## 原网络只读快照

核对 `network_snapshot` 能力与对应导出后调用 `jc_network_snapshot`，返回 `{schema_version,observed_at,network:{os,interfaces,routes,policy_rules}}`。接口包含原生索引、名称、状态、回环标记与实际地址／前缀；Windows 另返回原生硬件描述，不能仅凭用户可改的接口别名判断官方 VPN。路由保留目的前缀、接口及网关，平台可用时附带表、指标、协议、类型、标志及多下一跳；这些原生枚举按返回的 OS 解释。

Linux 使用独立限时 netlink 句柄读取所有 IP 路由表，包含 Tailscale 等非 main 表及多下一跳；路由 `source` 为首选源地址字面量，`scope` 为非零原生作用域（省略为 universe）；接口地址与策略规则的源／目的仍保留前缀。Windows 使用 IP Helper 原生表与接口元数据；macOS 使用原生 RIB，保留 IPv4／IPv6 掩码和接口作用域标志。不会把默认／分割默认出口转换成保护目标。Linux 的 `policy_rules` 是实际 IPv4／IPv6 路由策略数组，其他平台为 null，不能将“不提供”视为“没有规则”。每项包含 family、priority、table、action、flags、tos、可用的源／目的前缀，以及全部 `attributes:[{type,value_hex}]`；原始属性按 Linux UAPI 保留顺序、类型及字节，包含零 fwmark、掩码、UID／端口、L3 master 与未知选择器，未解释不代表不存在。读取使用独立 netlink socket、整次一秒预算和 4096 条上限；核对内核发送方、序号、端口、完整消息／属性长度，截断、中断、超时或超限均失败，不交付部分规则。未直接使用依赖中会丢失头字段或按错误宽度读协议的 RuleList。此投影尚不包含系统 DNS 或所有网络管理器状态，不能替代 S4-03 的操作所有权／恢复记录，也不能据此宣称规则优先级或出口选择已验收。

输出仍受 `MaxOutput` 限制，超限返回 `JC_LIMIT` 并保持长度为零，不交付截断快照。接口变化或读取失败只返回固定状态，不输出含地址的系统错误。可直接提供 `MaxOutput` 缓冲；查询容量与随后读取是两次独立观测，网络变化时所需长度可变。操作只读，但本身不是内核事务；应用网络变更前仍须重新核对原值与所有权。快照内容留在调用方，不自动写日志。

## 校园资源只读快照

`resource_snapshot` 由正式协议后端提供。`jc_session_resources` 需要活动句柄及 Start 返回的代次，返回 `{schema_version,generation,resources}`，代次为字符串。`resources` 包含 `ip_resources:[{ip_min,ip_max,protocol,port_min,port_max}]`、`domain_resources:{域名:[{protocol,port_min,port_max}]}`、`dns_records:{域名:[地址]}`、`campus_dns`、`campus_dns_enabled` 与 `underlay_interface`。后者为资源建立时核心当前选用的原网络接口偏好，空字符串表示使用系统路由；它不代替内核出口查询，不证明实时路由或接管已就绪。注入的外部拨号器未提供该观测时同样为空。数据直接取自该代实际交给拨号／解析层的解析结果，不重新登录、不重复请求服务器、读取代理文件或重写授权匹配器；应用／节点标识、认证材料及服务器原始响应不导出。

资源尚未发布时返回 `JC_BUSY`，应用在核心 ready 后读取，无需文件轮询。零代次返回 `JC_INVALID_ARGUMENT`；其他代次、停止期间及已结束会话返回 `JC_STALE_REQUEST`，已销毁句柄返回 `JC_INVALID_HANDLE`；认证方式查询不提供该数据。输入和返回缓冲区均不被保留；同代数据不因调用方修改而改变，下一代清空，结束后释放。无效或超限结果只报告状态；超过 `MaxOutput` 返回 `JC_LIMIT`，不截断，当前本地代理会话仍可运行，透明入口不得据缺失数据应用规则。

DNS 内置记录只解释服务器提供的解析数据，不单独授予业务端口访问；校园 DNS 开关表示配置允许使用，不代表已探测可达。协议／端口与保护规则仍以共用拨号／解析层为准。该快照用于解释资源与原路由的冲突，读取本身不启用透明访问，也不写本地日志。

## 保护策略更新

调用方须核对 `policy_update:true` 和 `jc_session_update_policy` 导出；ABI v1 兼容增补，不改变已有认证回应。连接代次由 Start 返回，修订在该代中严格递增，均使用十进制字符串。完整快照示例：

~~~json
{"schema_version":1,"generation":"1","revision":"1","protected":["192.168.50.0/24","fd7a:115c:a1e0::/48"],"campus":["192.168.50.17"]}
~~~

五个字段必填；空数组明确清除相应范围／选择，缺失、null、未知或重复字段、无效前缀／地址均返回 `JC_INVALID_ARGUMENT`，保留最后有效规则。保护前缀必须规范，不能用默认或分割默认路由充当保护范围；校园选择只接受具体 IPv4 地址，不接受前缀或 IPv6 校园访问。模型按最具体范围解释匹配，不把全部 RFC1918 地址当作实际局域网。

核对 `name_protection:true` 后，初始 `protection` 及实时更新还可携带 `protected_names` 和 `campus_names`；省略或空数组表示没有名称保护／例外，不继承旧值。名称规则示例为 `[{"kind":"suffix","value":"mesh.test"}]`，每个数组最多 4096 项。`suffix` 匹配该名称及以点分隔的子域，`exact` 只匹配完整名称，`prefix` 只接受无点的名称前缀，`single_label` 使用空值匹配不含点的名称。规则值使用规范小写 ASCII／ACE，拒绝根域、通配符、IP、空标签及畸形名称；原生 DNS 表达式须先按其实际语义推导，不直接复制成后缀规则。`campus_names` 只接受保护范围内的精确名称，不接受通配符或子域范围；无效完整更新保留最后有效规则。

受保护名称先于校园资源、静态解析和缓存判断，普通请求使用系统默认解析及原生拨号，保留绝对查询末尾的点和原生 IPv4／IPv6 连接选择；原生查询失败不尝试校园或备用公共解析。强制校园查询／保活直接拒绝，取消及关闭沿用所属解析任务的生命周期。非 ASCII 或畸形查询不跨越已安装的名称保护。精确校园名称例外只为该名称的连接选择校园路径，可覆盖该连接的重叠地址保护；其他名称和直接 IP 请求保留原保护。例外仍须学校 IP／域名、协议和端口授权，不以原出口回落掩盖失败。本扩展不配置系统 DNS，系统实际 NSS／分域提供者的覆盖限制见[架构说明](ARCHITECTURE.md)。

完整解析在会话锁外完成，提交时重新核对活动、停止状态、代次与修订，再一次替换不可变快照。旧代次、重复／倒序修订、停止期间及已结束会话返回 `JC_STALE_REQUEST`；销毁后的句柄返回 `JC_INVALID_HANDLE`；认证方式查询不接受规则，返回 `JC_UNSUPPORTED`。成功同步返回输入的生效代次，并确认该修订已提交，无需等待事件或轮询文件。下一代清空旧规则与修订，不继承其他配置的手动选择。

生产 SOCKS／HTTP 新拨号先应用保护，再进行服务器 IP／域名、协议与端口授权。命中保护且未明确选择校园时保留实际原网络出口；强制校园拨号、校园 DNS 与保活拒绝跨越该保护，不借机回退公共 DNS。明确选择同时要求该保护地址使用校园路径；普通代理与强制校园模式均继续核对服务器授权，未授权时返回错误，不改走原网络，也不授予额外权限。IPv4 映射与 IPv6 zone 统一进入保护／授权判断，带 zone 的映射 IPv4 先规范化再匹配；IP 入口拒绝未解析名称，名称保护先于解析判断，其余域名解析后继续检查地址保护。域名解析及 DNS 回退统一由解析器处理；最终解析失败即返回错误。只有已明确属于原网络的受保护名称使用原生名称拨号，不能借原生再次解析绕过其余地址策略。

本接口只确认核心后续连接使用的规则；名称解析结果与随后业务拨号共用解析开始时的快照，直接 IP 拨号取当前快照。不关闭已建立连接、不改系统路由／DNS，也不确认透明入口就绪。Qt `sessionStarted` 交付该代的字符串标识，随后 `initialProtectionApplied` 交付该代核心已接受的完整初始策略（修订 0）；IPv4 更新保留其中最后确认的名称字段，不从只读刷新隐式替换。`updatePolicy` 与 `readSnapshot(Network/Resources,generation)` 均在专属工作线程核对能力和可选导出后执行。`policyUpdated`／`snapshotReady` 共用 `RequestStatus` 分类，区分成功、待就绪、过期、无效、不支持、超限与失败；资源回应还核对库返回的代次。关闭期间的晚到结果按过期处理并清空快照内容，新会话丢弃旧操作的确认。缺少扩展时只报告该能力不可用，保留原有会话入口。Qt 已接入原网络模型及明确 IPv4／具体名称选择和撤回，名称／地址更新保留另一类已确认字段；名称规范化复用模型推导，保护范围及学校授权继续由核心唯一判断。网络变化自动协调和透明前端仍待接入，当前界面不宣称系统透明接管已经生效。会话控制连接与网关出口由 S4-05 单独验证。

## 事件与认证回应

事件包含 `schema_version/type/generation/sequence/status`。代次、序列号与请求标识为十进制字符串，避免 Qt JSON 数值精度损失。状态事件为 `state:starting/ready`；终态为 `type:terminal`，携带安全消息。`ready` 在认证未完成／未读时不能产生，每代最多一次。诊断只接受已登记 `code`，没有任意文本／服务端响应字段：`authentication_started/transport_connected/keepalive_retry/anti_mitm_failed/persistence_failed/manifest_cached/auth_detail_unavailable`。初始化／认证方式查询中的证书校验失败另发送阶段码 `tls_authentication_failed/tls_resources_failed/tls_node_probe_failed/tls_ip_tunnel_failed` 及原因码 `tls_unknown_authority/tls_hostname_mismatch/tls_certificate_time_invalid/tls_certificate_invalid`，终态仍为 `JC_TLS_TRUST`；时间错误包括过期及尚未生效。证书失败还按实际握手链发送 `tls_peer_chain_leaf_only`（对端仅发送叶证书）和 `tls_peer_self_signed`（叶证书的自签名验证通过），均只描述未受信证书，不作为接受依据；仅发送叶证书本身不能证明缺少中间证书。多节点证书失败与探测超时并存时，保留证书原因并返回 `JC_TLS_TRUST`，显式取消仍优先。只记录固定代码，不输出证书正文、服务器原始错误或请求 URL。宿主日志目标保持不变，SID、票据、签名、凭据、原始响应和报文不进入诊断。

队列最多保留 `MaxDiagnostics` 条诊断；超限立即返回 `JC_LIMIT`，不阻塞数据面或退出。另外保留两条状态、一个未读认证请求和一个终态的位置（查询结果占用该代的结果位置，不与 ready／认证并存），缓存另保留两个位置（见下文），六类会话观测各保留一个最新值，总数最多 `MaxDiagnostics + 12`；单个事件和图片受大小限制。未读认证不能回应；过期但未读的请求仍占据位置，避免重试积压图片。终态和清理均不依赖宿主消费诊断。

`authentication_cache` 是版本 1 的可选扩展；省略或 `enabled:false` 时不恢复或交付缓存。启用使用 `{enabled:true,account:"服务器确认账户",data:"Base64 的不透明核心材料"}`；首次认证只传 `enabled:true`。`account/data` 必须同时提供，账户不替代 `auth.username` 登录别名；解码后最多 `MaxAuthCache`（16 KiB）。查询认证方式不接受启用缓存。宿主只从系统安全存储提供这份材料，Base64 仅是 ABI 传输编码。

启用后接收 `type:authentication_cache,action:save,cache:{account,data}` 或 `action:invalidate` 事件；`data` 同样是 Base64。保存事件来自服务器确认后的快照，在资源获取／数据隧道建立之前即可交付；资源响应改变 Cookie 时再交付新快照，相同材料不重复交付。后续连接失败可在保存后产生非成功终态，保存事件不代表 ready。刷新会更新 Cookie；明确拒绝才产生失效事件，普通 Stop 不注销。宿主按活动配置作用域保存／移除，不把数据输出到诊断或日志。待交付的连续保存只保留最新一份，失效会丢弃旧保存，后续新认证的保存排在失效之后；最多占两个队列位置，停止不依赖存储或宿主消费。超过缓存上限只交付 `persistence_failed` 诊断，不中断已有效的连接。原生存储更小的实际上限仍须由宿主报告，不能回退到明文。

恢复不成功且缺少密码时终态为 `JC_CREDENTIALS_REQUIRED`，宿主提供一次必要凭据输入，不提交空密码。未启用认证缓存时不发送缓存保存／失效事件；会话观测是可忽略的增量事件。

~~~json
{
  "schema_version": 1, "type": "authentication",
  "generation": "1", "sequence": "2", "status": 0, "request_id": "1",
  "challenge": {"kind": "sms", "can_skip_secondary_auth": true}
}
~~~

~~~json
{
  "schema_version": 1, "generation": "1", "request_id": "1",
  "action": "submit", "code": "123456"
}
~~~

`jc_build_info.capabilities.max_auth_wait_ms` 为单次认证等待上限，目前五分钟，由核心设置 deadline；调用方 deadline 更早时优先生效。到期终态为 `JC_TIMEOUT`，停止／用户取消仍为 `JC_CANCELLED`，Qt 关闭认证窗口并提供重试。超时不接收已排队的晚到回应，新一代认证必须重新取得请求标识。

`action` 仅允许 `submit/cancel/confirm`；`confirm` 只用于可信设备登记，取消与确认均不能携带凭据或其他输入。重复、过期、旧代次或未读请求的回应返回 `JC_STALE_REQUEST`。取消和响应竞争时只接受一个回应，Stop 后的迟到回应不会交给下一代。

| challenge.kind | 内容／有效回应 |
| --- | --- |
| `sms/totp/radius` | `code`；仅请求允许时接受 `skip_secondary_auth:true`，该独立标志可与验证码一同提交 |
| `text_captcha` | base64 `image`；回应非空 `code` |
| `click_captcha` | base64 `image`；回应 `points:[{x,y}]/width/height`，点在图片范围内且数量受限 |
| `trusted_device` | 用户明确选择登记当前设备才回应 `action:confirm`，拒绝或关闭使用 `cancel`；无默认确认、验证码或设备标识输入 |
| `cas/oauth2` | `login_url`；回应 `callback_url`，仅接受无 userinfo 的 HTTP(S) URL |

验证码只接受 PNG／JPEG／GIF；压缩图片不超过 `MaxAuthImage`（128 KiB），宽高不超过 `MaxAuthDimension`（8192），总像素不超过 `MaxAuthPixels`（4,194,304，RGBA 约 16 MiB）。Go 在交付事件前检查图片头，Qt 在完整解码前复用同一上限并拒绝其他格式；点选输入和回应均最多 32 个点，回应画布也受像素上限约束。认证 HTTP 控制面通过同一 `Session.request` 限制解压后响应体为 8 MiB，超限返回 `JC_LIMIT`；取消、关闭响应体及已有的请求超时继续生效，此限制不作用于业务隧道流量。

桥接层不打开浏览器、不请求认证 URL。URL 和图片为目的明确的认证数据，不作为诊断日志输出；S2 接入真实校园时仍须验证登录／回调来源、域和认证标识，不能用语法验证代替来源验证。可信设备登记通过同一请求／回应契约显式确认；缺少处理器时不发送登记请求。未知后续服务和缺少类型的 token 步骤返回 `JC_AUTH_UNSUPPORTED`，Qt 提示服务器认证策略暂不支持，不落入通用文本输入，也不输出服务器原文。

## 验证与构建

~~~sh
python scripts/test-corelib.py
go -C corelib test -race -timeout 90s ./...
cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3
ctest --test-dir build/coreabi -C Release -V --output-on-failure
~~~

使用固定 Go 与已配置 Qt SDK；Windows 另需 S1-06 验证过的 cgo 编译器。独立宿主沿用 Unix c-archive、Windows 随包 DLL 方案；正式应用与安装包复用同一 CMake 核心 target，详情见 [开发说明](DEVELOPMENT.md)。

宿主以 C11、C++17 头文件编译并实际调用正式库，检查来源、ABI 不匹配、257 轮生命周期、缓冲区护栏和四个 QThread 调用，并在同一进程验证 GUI 心跳与 WebEngine JavaScript；这部分已取代 S1-06 模拟探针。另一个仅通过 `jc_abi_test` 构建标签启用、明确标为 `test_driver:true` 的驱动，复用同一导出／传输实现，验证跨 C ABI 的认证成功回应、输入覆盖后使用、忙错误、重复／旧代次回应、取消与重启；不访问网络、不作为 VPN 分发。

Go 回归覆盖严格配置、各类认证回应、事件积压、过期请求、慢清理超时、读者唤醒、并发启动、panic 脱敏和资源上限，并包含配置模糊测试。新增 `coreabi_protocol_test` 由测试 Go 网关驱动正式 C 宿主，经过实际 HTTP/TLS、短信认证、资源／选线／隧道握手、SOCKS 和 HTTP CONNECT 双向数据、活动连接停止及查询重启。网关只使用回环与测试资源地址；不是内置的生产替身。Go 还覆盖普通 HTTP、SOCKS UDP association、DNS／认证／IP 阶段取消、监听冲突回滚、会话失效和同 goroutine panic 交付。六组原生 CI 验证 C／Qt 宿主、性能与平台代理／自启动检查（Windows／macOS 各 11 项、Linux 各 12 项）及完整 Go 套件；race 在 Go 支持的五组平台执行，Windows ARM64 由固定 Go 明确不支持，但仍执行普通 Go 与真实 FFI 回归。宿主库启用 `GOEXPERIMENT=cgocheck2`，没有关闭指针检查。

S1-07 与 S1-08 的受控网关及六平台宿主已验证正式会话、Qt 认证窗口／查询、后台清理和代理收发，证据见计划。真实校园账号、TLS 生产策略、系统透明访问及 Clash 共存仍分别按 S2、S4—6 验收；S1-09 的实际安装包离线验收独立于回环网关。

2026-10-20，代码 `c66be1d` 的[六组原生宿主 CI](https://github.com/wtalioy/JustConnect/actions/runs/39356166583)全部通过，包含五组可用的 race 检查；[三平台应用回归](https://github.com/wtalioy/JustConnect/actions/runs/39356166708)各通过 25 包限定 Go 基线和 16 项应用测试。此为 S1-03 历史验收；S1-07／08 已接续正式协议和 Qt 受控回归，S1-04 的真实校园样本仍待验收。

2026-10-20，S1-07 最终修复 `0a81fe5` 的[六组原生 CI](https://github.com/wtalioy/JustConnect/actions/runs/39368117638)全部通过，六组各通过完整 Go 与上述三个宿主场景，支持的五组完整 race 通过；[三平台应用 CI](https://github.com/wtalioy/JustConnect/actions/runs/39368117501)各通过完整 18 包及 16 项应用测试。S1-07 已验收，后续范围保持上述区分。

## Qt 应用端口

`CoreEngine` 表达连接、认证方式查询、结构化认证回应、认证缓存更新／失效与停止能力；`EmbeddedCoreEngine` 负责 JSON／C ABI 边界。专属工作线程读取有界队列，并以一次一个事件的确认方式排队交付给应用线程。停止立即请求取消，随后等待清理终态；销毁中断泵并等待会话销毁，不卸载 Go runtime。认证和回应保留原始字符串代次／请求 ID，旧回应及取消均不会作用于新会话。缓存只在连接且显式启用的配置中传递，Qt 校验账户、规范 Base64 及长度后交付独立信号；查询端口新建不含凭据或缓存的配置。图片从事件内存解码，不落临时文件；SSO 使用事件给出的登录 URL 和会话保存的回调服务器。

配置模型仅保留 aTrust 与 ABI 支持字段，端口零关闭对应监听、监听固定在回环。S2-02 已删除 EasyConnect、TUN／路由、额外 CLI 参数及旧转发等控件／运行字段；旧协议要求显式确认 aTrust 入口。设置页与向导保存前调用 `jc_config_validate`，与启动复用同一 JSON 映射与 Go 严格解析；非法地址／认证／非回环监听、超限值及未知 JSON 字段仍被拒绝，不自动退回进程。构建显示使用实际已加载库的来源信息。共享 CMake 入口见 `cmake/CoreLibrary.cmake`；真实窗口／正式网关回归在根 CTest 和六平台原生宿主中使用同一 `tests/CoreEngineTests.cmake`。

S1-09 已验收：`a729296` 的[三平台应用回归](https://github.com/wtalioy/JustConnect/actions/runs/39383282228)与[六组实际包自检](https://github.com/wtalioy/JustConnect/actions/runs/39383294934)全部通过。同一最终源码的[六组原生回归](https://github.com/wtalioy/JustConnect/actions/runs/39383282309)全部通过。包内实际调用版本／ABI、无效启动拒绝、创建／停止／销毁；来源归档逐文件一致，脱离 Git 完整重建的应用也通过同一自检。实际 glibc／macOS 下限、预览签名与正式签名边界见计划及开发说明。

S2-03 为认证配置与查询事件兼容增补 `auth_id`／`sub_type` 字段；原始登录域与 URL 仍由服务器提供。新选择按完整身份匹配，旧配置只有唯一类型／登录域匹配时才继续；过期或歧义身份以 `JC_AUTH_METHOD_CHANGED` 结束，要求重新查询，不能退回列表第一项。

S2-03 的 `tls` 可省略（默认验证系统信任链及目标主机名）；`skip_verify:true` 仅接受调用者显式选择，不会因证书失败自动重试为不验证。可用 `ca_pem` 附加学校 CA，最多 16384 字节，非法证书在纯配置校验时拒绝。查询、认证 HTTP 和资源请求使用此会话策略；`allow_unverified_nodes:true` 可由当前配置显式允许节点探测、IP 与 TCP／L3 隧道跳过证书链和地址校验，默认 false，不影响认证／资源 HTTPS 或浏览器。连接开始发送固定诊断 `tls_node_verification_disabled`，认证方式查询不发送。Go 的 `atrust.ClientOptions.AllowUnverifiedNodes` 只派生节点策略，不修改调用者或认证策略；隧道仍禁用 TLS session tickets，未固定 TLS 版本。Go 的 `atrust.ClientOptions.TLSConfig` 与 `auth.NewSessionContext` 接受标准 `*tls.Config`，克隆后使用；调用者须按 Go 的 Config 约定保持证书池等引用只读。

终态 `JC_TLS_TRUST` 表示证书链／主机名失败，`JC_TLS_PROTOCOL` 表示握手协议失败，`JC_NETWORK_FAILURE` 表示可重试的网络连接／读写失败，`JC_PERMISSION_DENIED` 表示本地网络操作权限不足；超时继续使用 `JC_TIMEOUT`。权限、证书及协议失败不进入自动登录重试。Qt 查询及连接分别显示对应原因，事件不交付原始 TLS／URL／服务器错误文本。错误分类直接使用 Go 的证书错误、握手边界与网络错误类型，未匹配终端文字。规范依据：[Go TLS](https://pkg.go.dev/crypto/tls@go1.27.2)、[HTTP Transport](https://pkg.go.dev/net/http@go1.27.2#Transport)。

### 会话观测

`observation` 是带当前 `generation`／`sequence` 的结构化事件，包含 `stage`、`result` 和 UTC RFC3339 `observed_at`。阶段为 `authentication`、`restore`、`renewal`、`traffic`、`nodes`、`tunnel`；结果为 `running`、`succeeded`、`failed`、`required`、`disabled`、`unavailable`、`unknown`。时间表示该项实际观测时间，不能推断后续持续在线；没有事件时保持未知。事件不携带目标 URL、账户、票据或原始服务器响应。

每阶段最多保留一个未读观测，与诊断限额分开；慢读者取得最新值，序号可能有间隔。认证请求、缓存失效、终态仍保留原有交付保证。`JC_SESSION_INVALID` 表示服务器明确拒绝现有会话，须停止并由用户重新认证，不自动重放密码。`state:ready` 仅为通道／本地代理就绪，不能表示校园 DNS、分流与透明接管就绪。

### 流量保活配置

可选 `keepalive:{mode,url}` 支持 `auto`（省略时默认）、`target`、`off`。只关闭应用流量探测；认证续期和节点维护继续运行，普通断开则取消全部维护。探测复用现有续期循环，不另建维护线程。`auto` 仅向学校下发且有 UDP/53 授权的 DNS 发送根域 NS 查询；缺少能力报告 `traffic:unavailable`。`target` 仅接受标准 80/443 端口的 HTTP/HTTPS GET 目标，禁止用户信息、查询参数和片段，不跟随重定向，也不发送 Cookie／Authorization。URL 最大 8192 字节；自动／关闭模式可保留未启用的目标草稿。

学校配置使用 `JustConnect/KeepAliveMode` 与 `KeepAliveURL`，由 ProfileService 映射到连接配置；认证方式查询不传流量保活。缺少新模式时迁移旧 `KeepAlive:false` 为关闭，否则非空目标为指定目标，其余为自动；已有新模式优先，目标不因关闭而删除。导入复用同一迁移，导出保留模式及目标，旧布尔开关迁移后移除。早先版本已经删除的值无法还原，不猜测用户原选择。

目标解析仅使用学校资源内置映射或获授权的校园 DNS，不使用来源未知的共享缓存或公共 DNS 回退。`disable_remote_dns` 同样约束保活，自动 DNS 探测报告不可用，指定目标仍可使用资源内置映射或 IP。连接必须命中校园 IP／域名、协议和端口授权，不走原网络。HTTPS 默认校验证书并复用显式学校 CA 策略。单次探测总预算 10 秒且随会话取消。`traffic` 与 `renewal` 结果独立：网页／DNS 探测成功不代表票据续期，临时续期失败保留有效缓存；明确失效报告 `renewal:required`／`authentication:required`，停止一次并交付 `JC_SESSION_INVALID`，不自动登录。

<a id="raw-tun-fd"></a>
## 原始 IPv4 TUN fd 接入

正式 Linux 后端通过 `raw_ipv4_tun_fd:true` 和 `jc_session_attach_tun` 兼容增补 ABI v1；其他平台和测试驱动返回 `JC_UNSUPPORTED`。调用方先由权限助手验证设备来源、连接所有权与所在网络命名空间，完成地址／MTU／启用及所有权恢复准备，再向当前就绪连接代次交付 fd。该调用不配置地址、路由或 DNS，也不表示系统接管已经就绪。

fd 为调用期间借用的 `int32_t`，须支持读写、已设 `O_NONBLOCK`，每次读写一个原始 IPv4 包。核心先创建 `CLOEXEC` 副本，核对实际 TUN 类型、启用状态、MTU 及不同的有效 IPv4 源／对端地址，以内核 netlink 信息拒绝 PI、virtio、TAP、多队列和持久设备；不依赖 `TUNGETIFF` 中与 `NOFILTER` 共用位的 `NO_PI` 判断帧格式。MTU 须与内核一致并满足包入口的 576–65535 字节范围。调用不更改原 fd 的标志或所有权；失败关闭本次副本，成功后原 fd 可由调用方关闭，核心保留自己的引用。

Qt `CoreEngine::attachTUN(generation, fd, mtu)` 同步保留 `CLOEXEC` 引用后排队到专属核心线程，调用返回即可关闭调用方 fd；通过应用线程的 `tunAttached` 回应代次与 `RequestStatus`。停止期间回应过期，新会话丢弃旧操作；销毁释放尚在队列中的引用。其他平台／缺少能力返回不可用。设备应在原网络保护快照完成后创建，避免把自有捕获路由当成原网络；系统助手与会话的实际编排仍待接入。

需要自动发布时，先核对 `tun_dns_routes:true`，再用 `jc_session_attach_tun_dns`，或 Qt `attachTUN(generation, fd, mtu, true)`。原始 attach 保留调用方管理路由的行为。新模式在成功的 IPv4 校园 DNS 应答前发出 `dns_routes` 事件，含字符串 `generation`／`request_id` 和规范 IPv4 `addresses`；地址仅来自原问题的有效 IN Answer CNAME 链，不采用无关 Answer／Additional。发布前重核当前名称／地址保护，拒绝回环、非单播及自有源／对端；不据此增加协议／端口授权。

宿主通过 `dnsRoutesRequired` 接收事件，在所属助手成功确认路由后调用 `acknowledgeDNSRoutes`；结果通过 `dnsRoutesAcknowledged` 返回。Go 最多保留一个待确认事件，其他查询可取消地等待同一槽位，每个请求从进入发布等待起共用五秒预算；超时／取消删除未读请求。仅完整读取的当前请求可确认，探测缓冲区大小、其他代次、晚到及重复回应均不生效；该事件独立于认证请求。成功发布后才登记地址授权寿命并交付 DNS，应答保留原 TTL；失败／超时返回 SERVFAIL，停止中断等待并加入原有有界清理，不回落公共 DNS。当前追加路由仍保留至所属连接恢复，运行中策略变化与路由撤销／在途流量寿命协调待实现。

活动但未就绪返回 `JC_BUSY`；其他代次、停止／完成返回 `JC_STALE_REQUEST`；无效 fd、帧配置、MTU 或重复交付返回 `JC_INVALID_ARGUMENT`。仅一个所属设备被接收，停止／设备失败会中断 I/O 并等待全部包处理退出，文件设备 I/O 错误沿既有网络失败／权限／超时分类报告，重启须重新交付且不接受旧代次。核心在内核读回的 TUN peer:53 提供 UDP／TCP DNS，仅接受该设备源地址；此地址不转发到校园。复用学校资源、名称保护及校园 DNS 的 IP／协议／端口授权，保留 CNAME、TTL、错误响应及 TCP 重试；内置资源地址直接回答。请求随会话取消，UDP 按查询大小截断。当前透明入口仅 IPv4，AAAA 返回 NOTIMP；非校园／受保护名称返回 REFUSED，不走校园或公共 DNS 回退。校园 A／CNAME 回答另为原查询域名建立至多 4096 项的会话内地址授权绑定，TTL 不超过链中最短值及配置缓存寿命；零 TTL 留一秒首流交接窗口。透明新流仍匹配域名协议／端口、名称与 IP 保护；严格校园 DNS 上游不使用该绑定。Linux 应用通过下述 `dns_routes` 确认，在 DNS 应答前完成助手增量捕获；实际接管与有序停止已联验。完整原网络 DNS 分流、地址／流量寿命协调及其他平台仍待验收。
