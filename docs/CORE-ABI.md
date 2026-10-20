# JustConnect 内部 C ABI v1

公共入口为 [justconnect.h](../corelib/abi/justconnect.h)，Go 实现在同一 `corelib/` 模块的 `abi/` 与 `internal/bridge/`。S1-03 提供契约和传输；正式 VPN 会话在 S1-07 接入，Qt 后端在 S1-08 切换。

## 单一契约来源

[contract.json](../corelib/abi/contract.json) 集中定义版本、状态码、安全上限及上游基线。运行 `python scripts/generate-core-abi.py` 生成 `constants.h` 与 `internal/bridge/constants.go`；`--check` 只核对差异，普通三平台与六组 FFI CI 均执行。生成文件不手改；字段结构在 Go 类型中定义，本文件记录宿主语义。

构建提交与工作树状态由 Git 查询注入，不填写开发机目录、学校地址或账户。`jc_build_info` 返回当前 Go 版本、目标 OS／架构、JustConnect 完整提交、上游基线和由提交／工作树状态组成的本地版本。直接手动构建而没有 VCS 信息时明确返回 `unversioned/unknown`，不能作为可追溯发布产物。

当前 `embedded_vpn:false`、`policy_update:false`；异步启动、认证回应与有界事件传输可用。正式库的 Start 接受合法配置后产生 `starting` 和 `JC_UNSUPPORTED` 终态，不尝试连接、不产生 `ready`。S1-07 安装真实会话时再更新能力。

## C 边界与生命周期

仅使用固定宽度整数和有长度的字节缓冲区；句柄是单调递增、从不重用的整数，不是地址。没有跨边界对象、异常、字符串指针返回值、分配／释放配对或 Go 回调 Qt。

UTF-8 JSON 不带结尾 NUL。输入仅借用至调用返回，库在返回前完成复制和解析；宿主随后可覆盖或释放配置／认证回应。输出及标量结果由宿主分配，内存必须有效且互不重叠。库检查空指针、长度、容量和超限，不探测任意非空地址是否可访问。Go 不保留 C 缓冲区，也不返回 Go 内存。

`length/handle/generation` 输出在错误时归零，`JC_BUFFER_TOO_SMALL` 则返回所需长度。容量不足不写任何字节、不消费事件；可用空指针／零容量查询长度，再扩容读取同一事件。成功输出不补 NUL。

| 函数 | 行为 |
| --- | --- |
| `jc_abi_version()` | 返回 ABI 版本 |
| `jc_build_info(abi, output, capacity, length)` | 校验版本，返回构建来源和实际能力 JSON |
| `jc_session_create(abi, handle)` | 校验版本，创建空闲句柄；保留数量受契约限制 |
| `jc_session_start(handle, config, length, generation)` | 同步严格校验并复制配置，异步启动；返回代次 |
| `jc_session_read(handle, wait_ms, output, capacity, length)` | 有界等待一个 FIFO 事件；容量不足可重试 |
| `jc_session_respond(handle, response, length)` | 仅接受匹配、已读取且尚未消费的认证请求 |
| `jc_session_stop(handle, wait_ms)` | 先取消，再有界等待清理；重复停止有效句柄成功 |
| `jc_session_destroy(handle, wait_ms)` | 清理完成后失效、释放句柄；重复销毁已签发句柄成功 |

进程内只允许一个活动会话；其他 Start 返回 `JC_BUSY`。清理完成前不释放活动名额。等待超时返回 `JC_TIMEOUT`，可重试；未清理完的句柄不能重启。销毁请求从发起起即禁止该句柄重新启动。

每次成功 Start 增加代次，事件序列从 1 开始；前一代未读事件必须读完才能重启。Stop 保留认证和终态事件，唤醒阻塞读取。Destroy 成功后显式丢弃剩余事件，使借用会话的读取失效。结束且无剩余事件返回 `JC_END`；空闲等待到期返回 `JC_TIMEOUT`；正在停止且终态尚未入队时可返回 `JC_CANCELLED`，随后仍可读取终态。

导出可并发调用，不持有全局句柄锁等待网络、认证或宿主读取。`wait_ms` 不得超过契约上限。状态码没有自由格式错误文本；终态消息只由安全状态生成，不回传解析器原文、服务端响应或 panic 内容。

## JSON 配置

ABI v1 与 JSON schema 版本同步。示例为隔离测试地址，运行配置由宿主提供：

~~~json
{
  "schema_version": 1,
  "server": {"host": "vpn.example.invalid", "port": 443},
  "auth": {"method": "auth/psw", "username": "example-user", "password": "example-secret"},
  "listeners": {"socks": "127.0.0.1:1080", "http": "[::1]:1081"}
}
~~~

`schema_version/server.host/server.port` 必填。host 是 ASCII DNS 名或 IP，不是 URL／带端口地址，端口显式指定。其他字段可省略；`auth` 还接受 `phone/domain/totp_secret`，method 支持空值（由会话查询）、`auth/psw`、`auth/smsCheckCode`、`auth/cas`、`auth/httpsOauth2`。listener 空值不启用；非空必须是回环 IP:port。没有 CLI 附加参数、默认学校、TUN、路由／DNS 修改、跳过 TLS 或原始调试输出开关。

拒绝重复键、未知字段、非规范字段大小写、尾随 JSON、null、超深结构、无效 UTF-8、NUL 和 Unicode 替代字符。超限值不截断、不静默回退。无效输入只返回 `JC_INVALID_ARGUMENT`，不把账户、密码或输入片段写入错误。

## 事件与认证回应

事件包含 `schema_version/type/generation/sequence/status`。代次、序列号与请求标识为十进制字符串，避免 Qt JSON 数值精度损失。状态事件为 `state:starting/ready`；终态为 `type:terminal`，携带安全消息。`ready` 在认证未完成／未读时不能产生，每代最多一次。诊断只接受已登记 `code`，没有任意文本／服务端响应字段。

队列最多保留 `MaxDiagnostics` 条诊断；超限立即返回 `JC_LIMIT`，不阻塞数据面或退出。另外保留两条状态、一个未读认证请求和一个终态的位置，总数最多 `MaxDiagnostics + 4`；单个事件和图片受大小限制。未读认证不能回应；过期但未读的请求仍占据位置，避免重试积压图片。终态和清理均不依赖宿主消费诊断。

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

`action` 仅允许 `submit/cancel`；取消不能携带凭据。重复、过期、旧代次或未读请求的回应返回 `JC_STALE_REQUEST`。取消和响应竞争时只接受一个回应，Stop 后的迟到回应不会交给下一代。

| challenge.kind | 内容／有效回应 |
| --- | --- |
| `sms/totp/radius` | `code`；仅请求允许时接受 `skip_secondary_auth:true` |
| `text_captcha` | base64 `image`；回应非空 `code` |
| `click_captcha` | base64 `image`；回应 `points:[{x,y}]/width/height`，点在图片范围内且数量受限 |
| `cas/oauth2` | `login_url`；回应 `callback_url`，仅接受无 userinfo 的 HTTP(S) URL |

桥接层不打开浏览器、不请求认证 URL。URL 和图片为目的明确的认证数据，不作为诊断日志输出；真实协议接入时仍须验证登录／回调来源、域和认证标识，不能用语法验证代替来源验证。可信设备等新步骤须显式扩展契约，未知类型不落入通用文本输入。

## 验证与构建

~~~sh
python scripts/test-corelib.py
go -C corelib test -race -timeout 60s ./internal/bridge
cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3
ctest --test-dir build/coreabi -C Release -V --output-on-failure
~~~

使用固定 Go 与已配置 Qt SDK；Windows 另需 S1-06 验证过的 cgo 编译器。独立宿主沿用 Unix c-archive、Windows 随包 DLL 方案；正式应用的统一 CMake／打包仍在 S1-09。

宿主以 C11、C++17 头文件编译并实际调用正式库，检查来源、ABI 不匹配、257 轮生命周期、缓冲区护栏和四线程调用。另一个仅通过 `jc_abi_test` 构建标签启用、明确标为 `test_driver:true` 的驱动，复用同一导出／传输实现，验证跨 C ABI 的认证成功回应、输入覆盖后使用、忙错误、重复／旧代次回应、取消与重启；不访问网络、不作为 VPN 分发。

Go 回归覆盖严格配置、各类认证回应、事件积压、过期请求、慢清理超时、读者唤醒、并发启动、panic 脱敏和资源上限，并包含配置模糊测试。六组原生 CI 验证正式库与认证宿主；race 在 Go 支持的五组平台执行，Windows ARM64 由固定 Go 明确不支持，但仍执行普通 Go 与真实 FFI 回归。宿主库启用 `GOEXPERIMENT=cgocheck2`，没有关闭指针检查。

此验收不代表校园登录、正式 VPN 启停、协议协程清理或网络转发完成；这些由 S1-07、S1-04 的真实协议回归及后续网络任务交付。

2026-10-20，代码 `c66be1d` 的[六组原生宿主 CI](https://github.com/wtalioy/JustConnect/actions/runs/39356166583)全部通过，包含五组可用的 race 检查；[三平台应用回归](https://github.com/wtalioy/JustConnect/actions/runs/39356166708)各通过 25 包限定 Go 基线和 16 项应用测试。S1-03 已验收；S1-04 的真实协议／Qt 回归仍须随后续接入完成。
