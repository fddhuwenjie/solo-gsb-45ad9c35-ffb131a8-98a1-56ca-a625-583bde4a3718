# 工业传感器二进制帧重同步 API

基于 **Python 3.11 + FastAPI + Pydantic v2 + SQLite** 的服务，用于在可能从任意半帧
开始的原始字节流中重新定位、校验并解码工业传感器二进制帧。

核心能力：

- **协议注册**：声明同步字节、长度字段（偏移 / 宽度 / 端序 / 调整值）、DLE 风格转义
  规则、CRC-16 参数（内置常用预设，也可自定义 poly/init/refin/refout/xorout），以及
  带符号与定点缩放（`scale` / `divisor`，支持位域与 min/max）的字段布局。
- **重同步解码** `POST /decode`：提交 base64 字节流，服务按同步字节逐个扫描候选帧；
  长度越界、转义非法、CRC 失败的候选被跳过并从下一个同步字节重试；选择**最早结束且
  校验通过**的完整帧；两个不同起点的合法帧若在同一位置结束则判定为协议歧义，返回
  结构化 422。
- **编码下发** `POST /encode`：按已注册协议把字段物理值（`Decimal` 精确反算原始整数）
  组装成可直接下发的二进制帧：写入位域、补 0 未写比特、派生长度值与 CRC、执行 DLE
  转义并添加同步字节；结果在返回前强制经现有解码器回读校验，字段不一致直接拒绝返回。
- **不完整尾部保留**：流末尾尚未凑齐的帧（含 dangling 转义符、只出现一半的同步头）
  原样保留在 `tail` 中返回，可直接与后续到达的字节拼接后再次提交。
- **分批采集会话** `POST /sessions` + `POST /sessions/append` + `GET /sessions/{id}`：
  创建会话时固定协议**确切版本**；现场字节流按批到达时，服务把上次未决尾部拼到新分片前、
  沿用同一套重同步解码，只返回**本次新确定**的帧与丢弃区间（起止为会话累计字节位置），
  并返回新待决尾部与下一偏移。已接收偏移、尾部与本次响应一起持久化，重启可续；最近一次
  分片按同一偏移与内容重发返回原响应且不重复产出；同偏移不同内容、并发/乱序提交一律 409
  拒绝且不改状态；拼合数据超限或解码报错均不推进偏移。提交以接收偏移为版本号在数据库内
  compare-and-swap 落库，**多个服务实例共用同一 SQLite 文件**时竞争追加也不会互相覆盖。
- **序号连续性稽核（可选）**：创建会话时传 `sequence_audit: true` 启用（协议须声明有效位宽
  ≥2 的无符号整数序号字段，否则 422 拒绝创建）。每次成功追加只稽核**本次新确认**的有效帧，
  按序号位宽取模比较：相同记 `duplicate`，前进 2 步到不足半圈记 `suspected_gap` 并给出缺失
  数量，超过半圈记 `backward`，恰好半圈记 `indeterminate`（后两者不推断缺帧）；每个有效帧
  都成为下一帧的基准，坏帧与未决尾部不影响基准。稽核状态与分片状态、本次响应**同一条原子
  UPDATE** 落库：重试只重放原稽核结果，竞争/解码失败不计数也不推进基准，重启后继续。
  最近序号与累计缺失数按**十进制文本**无损落库——u64 原始序号达到 2⁶³、累计推断缺失数超出
  SQLite 有符号 64 位 INTEGER 上限时追加依然成功且数值逐位精确；旧库文件在启动时**就地透明
  迁移**（审计列由 INTEGER 重建为 TEXT，历史值原样保留），既有会话照常读取（边界示例见 4.7.4）。
- **换库检查点导出 / 导入** `GET /sessions/{id}/checkpoint` + `POST /sessions/import`：更换
  SQLite 数据库时，把会话在**同一已提交时刻**的确切协议版本与定义摘要、接收偏移、原始待决尾部、
  累计帧数、最近分片摘要与原响应、序号稽核进度导出为可移植 JSON；目标库只在已注册**摘要相同的
  确切协议版本**、该协议序号字段的**有效位宽与检查点稽核模数一致**（序号基准落在位宽原始范围内）、
  原响应尾部起点恰为**接收偏移减解码后尾部字节数**、无同名会话且检查点自洽时，在**一个
  `BEGIN IMMEDIATE` 事务内**按原 `session_id` 落库，否则整次失败、不覆盖现有状态；并发协议注册或
  竞争导入无法在核验与写入之间绕过检查。导入后跨分片解码与稽核无缝接续，最近分片重发仍返回原响应
  而不重复计数，超出 SQLite 有符号整数范围的稽核值保持精确（示例见 4.8）。
- **丢弃区间审计**：每次跳过都返回 `[start, end)` 区间与各候选的失败原因
  （`length_out_of_bounds` / `crc_failed` / `malformed_escape`）。
- **结果复用**：同一协议版本 + 输入字节 SHA-256 摘要命中 SQLite 缓存，响应中
  `cached=true`。
- **结构化错误**：字段越界、协议歧义、非法协议声明均返回统一错误信封的 HTTP 422。

## 一条命令启动

```bash
docker compose up --build
```

容器把宿主机 **8000 端口**映射到容器内 8000（compose 中的 `ports: ["8000:8000"]`，
镜像 `EXPOSE 8000`，uvicorn 监听 `0.0.0.0:8000`）。服务监听
<http://localhost:8000>，交互式文档在 <http://localhost:8000/docs>。
若 8000 被占用，把 compose 映射改为 `"8001:8000"` 即可从 <http://localhost:8001> 访问。
SQLite 数据文件保存在命名卷 `resync-data`（容器内 `/data/resync.db`）。

本地（无 Docker）启动：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RESYNC_DB_PATH` | `/data/resync.db` | SQLite 文件路径 |
| `RESYNC_MAX_DECODE_BYTES` | `1048576` | 单次解码原始字节上限（超出返回 413） |

## 快速示例

### 1. 注册协议

```bash
curl -s -X POST localhost:8000/protocols -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line",
  "version": 1,
  "sync": [170, 85],
  "endian": "big",
  "length_field": {"offset": 4, "size": 1},
  "crc": {"preset": "CRC-16/CCITT-FALSE", "offset": 6},
  "fields": [
    {"name": "seq",  "type": "u8",  "offset": 0},
    {"name": "addr", "type": "u8",  "offset": 1},
    {"name": "temp", "type": "s16", "offset": 2, "scale": "0.01"}
  ],
  "sequence_field": "seq",
  "max_frame_length": 64
}'
```

帧的逻辑视图（同步字节之后）：

```
offset  0    1    2    3    4      5    6    7    8
        seq  addr temp_hi temp_lo len  st   crc_hi crc_lo x
└──────────── CRC 覆盖（offset 6..7 之外的全部逻辑字节）────────┘
```

内置 CRC 预设：`CRC-16/CCITT-FALSE`、`CRC-16/XMODEM`、`CRC-16/X25`、
`CRC-16/MODBUS`、`CRC-16/IBM-SDLC`、`CRC-16/ARC`、`CRC-16/USB`、`CRC-16/DNP`；
也可以省略 `preset`，直接给 `poly/init/refin/refout/xorout`。

### 2. 解码（可从半帧开始）

```bash
curl -s -X POST localhost:8000/decode -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line",
  "payload_b64": "AZm...（base64，可包含噪声、坏帧、半帧尾部）"
}'
```

响应示例：

```json
{
  "protocol_id": "sensor-line",
  "version": 1,
  "input_digest": "b4f07670…",
  "frames": [
    {
      "start": 2,
      "end": 13,
      "logical_length": 9,
      "sequence": 10,
      "crc_ok": true,
      "fields": [
        {"name": "seq",  "offset": 0, "size": 1, "raw": 10,   "value": 10,    "signed": false},
        {"name": "addr", "offset": 1, "size": 1, "raw": 3,    "value": 3,     "signed": false},
        {"name": "temp", "offset": 2, "size": 2, "raw": 2345, "value": 23.45, "signed": true}
      ]
    }
  ],
  "discarded": [
    {"start": 0, "end": 2, "reason": "noise", "failed_attempts": []}
  ],
  "tail": {"start": 13, "end": 18, "payload_b64": "qlUKAAk="},
  "frame_count": 1,
  "consumed": 13,
  "cached": false
}
```

- `start` / `end`：帧在**原始字节流**中的半开区间 `[start, end)`（端到端，含同步字节）。
- `discarded`：被放弃的字节区间；`reason` 为 `noise`（其间没有可识别同步头）或
  `resync_failed_checks`，后者的 `failed_attempts` 给出每个候选同步点的失败细节。
- `tail`：流尾部无法确认成帧的字节，base64 原样回传，收到新数据后拼接重试即可。
- 再次提交完全相同的字节流时 `cached=true`。

### 3. 编码一帧（可直接下发）

`POST /encode` 按已注册协议反向组装一帧。请求给出 `protocol_id`、`version`（可省略，
取最新版本）、`logical_length`（逻辑体长度，即同步字节之后、转义之前的字节数）和
`fields`（字段名 → 物理值）。字段值建议用字符串给出精确小数（裸 JSON 数字也会按
`Decimal` 解析，不会经过二进制浮点）：

```bash
curl -s -X POST localhost:8000/encode -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line",
  "version": 1,
  "logical_length": 9,
  "fields": {
    "seq": 1,
    "addr": 3,
    "temp": "23.45",
    "state": 7,
    "alarm": 1
  }
}'
```

响应示例：

```json
{
  "protocol_id": "sensor-line",
  "version": 1,
  "wire_b64": "qlUBAwkJ…",
  "logical_b64": "AQMJCSVl…",
  "logical_length": 9,
  "wire_length": 11,
  "length_value": 9,
  "crc": "65A5",
  "fields": [
    {"name": "seq",  "offset": 0, "size": 1, "value": "1",     "raw": 1,    "wire": 1,    "bit_offset": null, "bit_width": null, "signed": false},
    {"name": "addr", "offset": 1, "size": 1, "value": "3",     "raw": 3,    "wire": 3,    "bit_offset": null, "bit_width": null, "signed": false},
    {"name": "temp", "offset": 2, "size": 2, "value": "23.45", "raw": 2345, "wire": 2345, "bit_offset": null, "bit_width": null, "signed": true},
    {"name": "state", "offset": 5, "size": 1, "value": "7",    "raw": 7,    "wire": 7,    "bit_offset": 0, "bit_width": 3, "signed": false},
    {"name": "alarm", "offset": 5, "size": 1, "value": "1",    "raw": 1,    "wire": 1,    "bit_offset": 3, "bit_width": 1, "signed": false}
  ]
}
```

- `wire_b64`：`同步字节 || 转义后的逻辑体`，base64 解码后即可直接下发。
- `logical_b64`：同步字节之后、未转义的逻辑体；未被任何字段写入的比特保证为 0。
- `length_value` / `crc`：实际写入长度字段的原始值（`logical_length - adjustment`）
  与实际计算并写入的 CRC-16（大写十六进制）。
- `logical_length` / `wire_length`：实际逻辑长度与线上长度（开启转义时后者更大）。
- `fields[].raw` 为按 `value × divisor ÷ scale` 反算的有符号原始整数；
  `fields[].wire` 为放到线上的无符号值（有符号字段为二补码，位域为位域内整数值）。

编码规则与校验：

- 服务用 `Decimal` 执行 `raw = value × divisor ÷ scale`，结果必须是**精确整数**且
  满足字段位宽（含位域宽度）与 `min`/`max`，否则 422。
- 多个字段覆盖同一比特时，只允许写入相同的值；冲突返回
  `OVERLAPPING_WRITE_CONFLICT` 422（details 给出字节/比特与冲突字段）。
- 字段不得占用长度字段或 CRC 的派生位置（`DERIVED_POSITION_CONFLICT`）。
- 字段全部写入后才写长度值与 CRC，随后执行转义、添加同步字节。
- 返回前强制把 `wire_b64` 送入现有 `/decode` 解码器回读；帧数不为 1、尾部非空或任一
  字段值与请求不一致时返回 `ENCODE_VERIFICATION_FAILED` 422，不下发该帧。

### 4. 分批采集会话（跨分片 / 重试 / 重启续传）

当现场字节流分批到达时，用一个**采集会话**把分片串成同一条逻辑字节流，服务保证每帧只被
产出一次。会话在创建时就**固定协议的确切版本**（不接受“最新版本”省略写法）。

#### 4.1 创建会话

```bash
curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line",
  "version": 1
}'
```

响应：

```json
{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "protocol_id": "sensor-line",
  "version": 1,
  "received_offset": 0,
  "next_offset": 0,
  "tail": {"start": 0, "end": 0, "payload_b64": ""},
  "frames_total": 0
}
```

#### 4.2 追加分片

`POST /sessions/append` 提交 `session_id`、`expected_offset`（期望接收偏移，即上一次响应的
`next_offset`；首个分片填 0）与**非空** base64 分片 `chunk_b64`。服务每次把**上次未决尾部
拼到新分片之前**（`tail || chunk`），沿用现有重同步解码，只返回**本次新确定**的帧与丢弃区间，
其 `start`/`end` 已统一换算成**会话累计字节位置**，并返回新的待决尾部与下一偏移。

把 `噪声2字节 + 完整帧1 + 帧2前4字节` 作为第 1 片（共 17 字节）：

```bash
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 0,
  "chunk_b64": "EjSqVQEDCSkJAHWbAKpVAgM="
}'
```

响应（只含本次新确定的帧；帧 2 的前 4 字节进入 `tail`）：

```json
{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "protocol_id": "sensor-line",
  "version": 1,
  "received_offset": 0,
  "next_offset": 17,
  "frames": [
    {"start": 2, "end": 13, "logical_length": 9, "sequence": 1, "crc_ok": true, "fields": [ ... ]}
  ],
  "discarded": [
    {"start": 0, "end": 2, "reason": "noise", "failed_attempts": []}
  ],
  "tail": {"start": 13, "end": 17, "payload_b64": "qlUCAw=="},
  "frame_count": 1,
  "frames_total": 1,
  "replayed": false
}
```

第 2 片用上次的 `next_offset=17` 作为 `expected_offset`，只发帧 2 剩余的 7 字节
（`/2oJAKqKAA==`）。服务把上片尾部 `aa 55 02 03` 接到本片前面重解，帧 2 在累计偏移
`[13, 24)` 处补齐：

```bash
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 17,
  "chunk_b64": "/2oJAKqKAA=="
}'
```

```json
{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "version": 1,
  "received_offset": 17,
  "next_offset": 24,
  "frames": [
    {"start": 13, "end": 24, "logical_length": 9, "sequence": 2, "crc_ok": true, "fields": [ ... ]}
  ],
  "discarded": [],
  "tail": {"start": 24, "end": 24, "payload_b64": ""},
  "frame_count": 1,
  "frames_total": 2,
  "replayed": false
}
```

要点：

- 第 1 片已返回的帧与丢弃区间**不会**在第 2 片响应里重复出现；被拆开的帧（含跨片的同步头、
  dangling 转义符）只在补齐那一片的响应中出现一次。
- `frames`/`discarded` 的偏移是**会话累计位置**；`tail.start/end` 也是累计位置，
  `tail.payload_b64` 是该尾部的原始字节。
- `received_offset` 是本次追加**之前**已接收的字节数，`next_offset` 是下一次应填的
  `expected_offset`，`frames_total` 是整个会话累计确认的帧数。

#### 4.3 重试（幂等）与冲突

网络超时等情况下，把**最近一次分片**按同一 `expected_offset` 和**完全相同的内容**重发即可：
服务返回与上次完全一致的响应，只是 `replayed: true`，不会重复产出帧、`frames_total` 不变。

```bash
# 与第 2 片完全相同的重发
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 17,
  "chunk_b64": "/2oJAKqKAA=="
}'
# -> 200，响应体同上，但 "replayed": true，frames_total 仍为 2
```

以下提交一律 **409 `SESSION_APPEND_CONFLICT` 且不改变任何状态**：

- **同偏移、不同内容**（试图改写已提交分片）：`details.reason = "content_mismatch"`，
  并给出 `committed_sha256` / `submitted_sha256`；
- **乱序 / 跳跃提交**（`expected_offset` 不等于服务端 `received_offset`，含迟到的旧分片、
  并发抢跑）：`details.reason = "offset_mismatch"`，并给出当前 `next_offset`。

```bash
# 同偏移不同内容 -> 409 content_mismatch
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 17,
  "chunk_b64": "WFhYWA=="
}'

# 期望偏移跳跃 -> 409 offset_mismatch
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 99,
  "chunk_b64": "WVk="
}'
```

同一会话的并发追加按会话加锁串行化；跨进程/多实例共用同一 SQLite 文件时，提交本身以
**接收偏移为版本号的 compare-and-swap**（`UPDATE ... WHERE received_offset = <读取时偏移>`）
在数据库内核对读取时的偏移仍有效，新偏移、待决尾部、累计帧数、最近分片与响应作为**一个状态**
原子生效。因此两个**不同**分片在同一偏移竞争时，恰有一个成功、另一个 409
（`content_mismatch`）；两个**相同**分片竞争时，一个正常提交、另一个作为重放返回
（`replayed: true`），绝不重复计数。

#### 4.4 超限与解码报错都不推进偏移

上次待决尾部与新分片**拼合后**的字节数超过 `RESYNC_MAX_DECODE_BYTES` 时返回 413
`PAYLOAD_TOO_LARGE`（`details.size` 为拼合后的大小）；解码过程中出现硬错误（如
`AMBIGUOUS_FRAME`、`FIELD_OUT_OF_BOUNDS`）时返回相应 422。两种情况下会话状态都保持在追加
之前：`received_offset`、`tail`、`frames_total` 与最近一次成功响应均不变，客户端可在排查后
用**相同的偏移**重发一个更短/修正后的分片。空分片（解码后 0 字节）为 422
`VALIDATION_ERROR`，非法 base64 为 422 `INVALID_BASE64`。

#### 4.5 进度查询与重启续传

```bash
curl -s localhost:8000/sessions/00e49c0d66904047837921d05a3090d6
```

```json
{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "protocol_id": "sensor-line",
  "version": 1,
  "received_offset": 24,
  "next_offset": 24,
  "tail": {"start": 24, "end": 24, "payload_b64": ""},
  "frames_total": 2,
  "last_chunk_offset": 17,
  "last_chunk_sha256": "5a77d65f01fa07275b780aacebfc81515b6056423a41608ed04fbe85d7c0f456",
  "created_at": "2026-10-05 15:40:59",
  "updated_at": "2026-10-05 15:40:59"
}
```

已接收偏移、待决尾部、累计帧数与最近一次分片（偏移 + SHA-256 + 原响应）在每个成功追加时
以**接收偏移为守卫的同一条原子 UPDATE** 写入 SQLite（默认 `/data/resync.db`，见上方启动/卷
配置）。服务重启后用 `GET /sessions/{id}` 读取进度，把最近一次未确认的分片按
`last_chunk_offset` 重发即可拿到原响应（`replayed: true`），随后用新的 `next_offset` 继续，
不会丢帧也不会重复产出。会话不存在返回 404 `SESSION_NOT_FOUND`。

#### 4.6 多实例共用同一 SQLite（副本部署）

可以启动多个服务实例指向**同一个 SQLite 数据库文件**（同一 `RESYNC_DB_PATH`），会话追加的
正确性不依赖进程内锁：提交时在数据库内核对读取时的接收偏移仍有效才落库，竞争落败的实例会
重新读取最新状态，再按 4.3 的约定判定（同偏移同内容 → 重放原响应；同偏移不同内容 → 409
`content_mismatch`；过期/跳跃偏移 → 409 `offset_mismatch`），落败方不改动任何状态。

本地起两个实例（注意用可写的数据库路径）：

```bash
# 终端 1
RESYNC_DB_PATH=/tmp/resync-shared.db uvicorn app.main:app --host 0.0.0.0 --port 8000
# 终端 2（同一数据库文件）
RESYNC_DB_PATH=/tmp/resync-shared.db uvicorn app.main:app --host 0.0.0.0 --port 8001
```

调用方式与单实例完全一致，客户端可任选一个实例：

```bash
# 在实例 8000 上建会话、提交第 1 片
curl -s -X POST localhost:8000/protocols -H 'Content-Type: application/json' -d '{ ... }'
curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' \
  -d '{"protocol_id": "sensor-line", "version": 1}'
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' \
  -d '{"session_id": "<sid>", "expected_offset": 0, "chunk_b64": "EjSqVQEDCSkJAHWbAKpVAgM="}'

# 实例 8001 立即看到 8000 提交的进度，并可继续追加第 2 片
curl -s localhost:8001/sessions/<sid>
curl -s -X POST localhost:8001/sessions/append -H 'Content-Type: application/json' \
  -d '{"session_id": "<sid>", "expected_offset": 17, "chunk_b64": "/2oJAKqKAA=="}'
```

两个实例同时读到同一 `next_offset` 并各自提交**不同**分片时，恰有一个返回 200，另一个收到
409 `content_mismatch`；提交**相同**分片（如超时重试打到另一实例）时，一个正常提交、另一个
返回 `replayed: true` 的原响应，`frames_total` 不重复累计。原有的
`docker compose up --build` 单实例启动方式保持不变（命名卷 `resync-data` 内的数据库文件同样
可以直接挂给第二个容器实例共用）。

**同时启动与旧库升级。** 两个实例若在服务启动时同时打开同一个**旧版**数据库文件（例如
`sessions.audit_last_sequence` / `audit_missing_total` 仍是 INTEGER、或稽核列尚不存在），
补列、列类型检查与 TEXT 重建在**同一个数据库写事务**（`BEGIN IMMEDIATE`）内完成：只有一个
实例执行升级，其余实例在 SQLite 写锁上等待（最长 30 秒），拿到锁后**重新判断表结构**，发现
已是新结构便直接放行——不会重复 `ALTER TABLE`、不会重建第二遍，启动均成功。升级事务要么整体
提交、要么整体回滚；升级中途失败（含进程被杀）时原 `sessions` 表与全部历史行原样保留，也不会
留下临时重建表，**再次启动自动重试**即可完成升级。升级完成后两个实例都能查询旧会话、重放其
最近分片并继续追加（对应 `tests/test_sessions_migration_concurrency.py`）。

#### 4.7 序号连续性稽核（可选）

单序列采集会话可以在**创建时**启用序号连续性稽核：请求体加 `"sequence_audit": true`。
被固定的协议必须声明 `sequence_field`，且该字段是**有效位宽 ≥ 2 的无符号整数**（`u*` 类型且
未置 `signed`；位域按 `bit_width` 计），否则创建被拒绝（422 `SEQUENCE_AUDIT_UNSUPPORTED`）。
未启用的会话与既有会话行为完全不变（响应中 `sequence_audit` 为 `null` 或不出现）。

##### 4.7.1 启用稽核的会话

```bash
curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line",
  "version": 1,
  "sequence_audit": true
}'
```

```json
{
  "session_id": "9c7a2af3e7214ac3b06767c42df700f0",
  "protocol_id": "sensor-line",
  "version": 1,
  "received_offset": 0,
  "next_offset": 0,
  "tail": {"start": 0, "end": 0, "payload_b64": ""},
  "frames_total": 0,
  "sequence_audit": {
    "bit_width": 8,
    "last_sequence": null,
    "duplicates": 0,
    "suspected_gaps": 0,
    "backwards": 0,
    "indeterminates": 0,
    "missing_total": 0
  }
}
```

协议不满足条件时创建被拒绝，例如序号字段未声明、是有符号类型或有效位宽不足两位：

```bash
curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' -d '{
  "protocol_id": "no-seq-protocol",
  "version": 1,
  "sequence_audit": true
}'
# -> 422 {"error": {"code": "SEQUENCE_AUDIT_UNSUPPORTED", "message": "…",
#        "details": {"sequence_field": null, "bit_width": null, "min_bit_width": 2, …}}}
```

##### 4.7.2 追加时的稽核结果（含跨分片）

每次**成功**追加只稽核本次新确认的有效帧：按序号字段位宽取模（上例 `bit_width=8`，模 256，
半圈 128）比较相邻原始序号——相同记 `duplicate`；前进 1 步为正常；前进 2 步到不足半圈记
`suspected_gap` 并给出 `missing` 缺失数量；超过半圈记 `backward`；恰好半圈记
`indeterminate`（`backward` / `indeterminate` 都不推断缺帧）。**每个有效帧都会成为下一帧的
比较基准**；CRC 失败等坏帧与未决尾部不参与、也不移动基准。

第 1 片含序号 1、2、4 三帧（缺 3）：

```bash
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "9c7a2af3e7214ac3b06767c42df700f0",
  "expected_offset": 0,
  "chunk_b64": "qlUBAwAACQAZ3gCqVQIDAAAJAMFcAKpVBAMAAAkAYHkA"
}'
```

响应的 `sequence_audit` 给出**本次异常**（帧的会话偏移、前后序号、类型）与各类累计次数：

```json
{
  "received_offset": 0,
  "next_offset": 33,
  "frames": [ {"start": 0, "end": 11, "sequence": 1, …}, {"start": 11, "end": 22, "sequence": 2, …}, {"start": 22, "end": 33, "sequence": 4, …} ],
  "sequence_audit": {
    "bit_width": 8,
    "last_sequence": 4,
    "anomalies": [
      {"type": "suspected_gap", "frame_start": 22, "frame_end": 33,
       "previous_sequence": 2, "sequence": 4, "missing": 1}
    ],
    "duplicates": 0,
    "suspected_gaps": 1,
    "backwards": 0,
    "indeterminates": 0,
    "missing_total": 1
  },
  "replayed": false
}
```

跨分片：序号 5 的帧被拆开，第 2 片只带其前 4 字节（`qlUFAw==`），该帧进入未决尾部、**暂不
稽核**（`anomalies` 为空，`last_sequence` 仍为 4）；第 3 片补齐该帧并带来序号 7 的帧时，
两帧一起判定（5 正常接续，7 相对 5 缺 1 帧）：

```bash
# 第 2 片：帧 5 的前 4 字节 -> 未决尾部，不稽核
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "9c7a2af3e7214ac3b06767c42df700f0",
  "expected_offset": 33,
  "chunk_b64": "qlUFAw=="
}'

# 第 3 片：帧 5 剩余字节 + 帧 7 -> 帧 5 在此片确认，帧 7 触发 suspected_gap
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "9c7a2af3e7214ac3b06767c42df700f0",
  "expected_offset": 37,
  "chunk_b64": "AAAJANgYAKpVBwMAAAkAuPsA"
}'
```

```json
{
  "received_offset": 37,
  "next_offset": 55,
  "frames": [ {"start": 33, "end": 44, "sequence": 5, …}, {"start": 44, "end": 55, "sequence": 7, …} ],
  "sequence_audit": {
    "bit_width": 8,
    "last_sequence": 7,
    "anomalies": [
      {"type": "suspected_gap", "frame_start": 44, "frame_end": 55,
       "previous_sequence": 5, "sequence": 7, "missing": 1}
    ],
    "duplicates": 0,
    "suspected_gaps": 2,
    "backwards": 0,
    "indeterminates": 0,
    "missing_total": 2
  },
  "replayed": false
}
```

##### 4.7.3 重试、失败与进度查询

稽核进度与分片状态、本次响应作为**一个状态**原子落库，因此：

- **同分片重试**（同偏移同内容）只重放原响应，`sequence_audit` 区块逐字节相同，异常不重复
  计数、基准不再推进；
- **竞争落败**（409）与**解码失败**（422/413）不增加任何异常计数、不推进基准；
- **服务重启**后从持久化的 `last_sequence` 继续判定。

```bash
# 与第 3 片完全相同的重发 -> 200，"replayed": true，sequence_audit 与上次完全一致
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "9c7a2af3e7214ac3b06767c42df700f0",
  "expected_offset": 37,
  "chunk_b64": "AAAJANgYAKpVBwMAAAkAuPsA"
}'

# 进度查询：最近序号 + 各类累计异常次数
curl -s localhost:8000/sessions/9c7a2af3e7214ac3b06767c42df700f0
```

```json
{
  "received_offset": 55,
  "next_offset": 55,
  "frames_total": 5,
  "sequence_audit": {
    "bit_width": 8,
    "last_sequence": 7,
    "duplicates": 0,
    "suspected_gaps": 2,
    "backwards": 0,
    "indeterminates": 0,
    "missing_total": 2
  }
}
```

##### 4.7.4 u64 大序号与累计缺失越界（无损持久化，可执行边界示例）

序号字段可以是任意无符号整数宽度（最大 64 位）。当原始序号达到甚至超过 2⁶³，或累计推断缺失数
超出 SQLite INTEGER 的上限（2⁶³ − 1）时，追加依然正常成功：`last_sequence` 与 `missing_total`
以**十进制文本**无损持久化（SQLite INTEGER 是有符号 64 位，直接存不下这些值），追加响应与进度
查询始终返回精确整数。服务启动时旧数据库被**就地透明迁移**（两个宽审计列由 INTEGER 重建为 TEXT，
历史值按原数值转换）；补列与重建在单个数据库写事务内完成，多个实例同时启动同一旧库时后到者等待
写锁后重新判断结构，升级失败整体回滚、保留原表与数据并在下次启动重试（见 4.6），既有会话、最近
响应重放与多实例共用行为完全不变。

下面用 64 位序号协议 `sensor-line64`（逻辑体 16 字节：`seq` u64 @0、`addr` u8 @8、长度 u8 @12、
CRC-16/CCITT-FALSE @14，线帧长 18 字节）演示两个边界场景。先注册协议并创建启用稽核的会话：

```bash
curl -s -X POST localhost:8000/protocols -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line64",
  "version": 1,
  "sync": [170, 85],
  "endian": "big",
  "length_field": {"offset": 12, "size": 1},
  "crc": {"preset": "CRC-16/CCITT-FALSE", "offset": 14},
  "fields": [
    {"name": "seq",  "type": "u64", "offset": 0},
    {"name": "addr", "type": "u8",  "offset": 8}
  ],
  "sequence_field": "seq",
  "max_frame_length": 64
}'

curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line64",
  "version": 1,
  "sequence_audit": true
}'
# -> 201 {"session_id": "2f5a5566f29748c4b74c85d539c6276b", ...,
#        "sequence_audit": {"bit_width": 64, "last_sequence": null, ...}}
```

**场景一：原始序号跨过 2⁶³。** 一片携带序号 2⁶³−1 与 2⁶³ 两帧（各 18 字节）：

```bash
curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "2f5a5566f29748c4b74c85d539c6276b",
  "expected_offset": 0,
  "chunk_b64": "qlV//////////wMAAAAQAM4TqlWAAAAAAAAAAAMAAAAQADOH"
}'
```

```json
{
  "received_offset": 0,
  "next_offset": 36,
  "frames": [
    {"start": 0,  "end": 18, "sequence": 9223372036854775807, "crc_ok": true, "fields": [ ... ]},
    {"start": 18, "end": 36, "sequence": 9223372036854775808, "crc_ok": true, "fields": [ ... ]}
  ],
  "sequence_audit": {
    "bit_width": 64,
    "last_sequence": 9223372036854775808,
    "anomalies": [],
    "duplicates": 0,
    "suspected_gaps": 0,
    "backwards": 0,
    "indeterminates": 0,
    "missing_total": 0
  },
  "frame_count": 2,
  "frames_total": 2,
  "replayed": false
}
```

2⁶³−1 → 2⁶³ 是模 2⁶⁴ 的正常一步（无异常），基准精确落在 `9223372036854775808`（= 2⁶³），
不再受 SQLite 有符号 64 位上限约束。

**场景二：累计推断缺失数越过 2⁶³ − 1。** 新建会话，依次确认序号 0、2⁶³−1、0、2⁶³−1 四帧
（模 2⁶⁴ 的半圈是 2⁶³）：

```bash
curl -s -X POST localhost:8000/sessions -H 'Content-Type: application/json' -d '{
  "protocol_id": "sensor-line64",
  "version": 1,
  "sequence_audit": true
}'
# -> 201 {"session_id": "360c623ab16b46fba20019dfe285fc92", ...}

curl -s -X POST localhost:8000/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "360c623ab16b46fba20019dfe285fc92",
  "expected_offset": 0,
  "chunk_b64": "qlUAAAAAAAAAAAMAAAAQAGT5qlV//////////wMAAAAQAM4TqlUAAAAAAAAAAAMAAAAQAGT5qlV//////////wMAAAAQAM4T"
}'
```

```json
{
  "received_offset": 0,
  "next_offset": 72,
  "sequence_audit": {
    "bit_width": 64,
    "last_sequence": 9223372036854775807,
    "anomalies": [
      {"type": "suspected_gap", "frame_start": 18, "frame_end": 36,
       "previous_sequence": 0, "sequence": 9223372036854775807,
       "missing": 9223372036854775806},
      {"type": "backward", "frame_start": 36, "frame_end": 54,
       "previous_sequence": 9223372036854775807, "sequence": 0,
       "missing": null},
      {"type": "suspected_gap", "frame_start": 54, "frame_end": 72,
       "previous_sequence": 0, "sequence": 9223372036854775807,
       "missing": 9223372036854775806}
    ],
    "duplicates": 0,
    "suspected_gaps": 2,
    "backwards": 1,
    "indeterminates": 0,
    "missing_total": 18446744073709551612
  },
  "frame_count": 4,
  "frames_total": 4,
  "replayed": false
}
```

两次疑似缺帧各推断缺失 2⁶³ − 2 帧，累计 `missing_total` = 2⁶⁴ − 4 = 18446744073709551612，
超出有符号 64 位仍逐位精确；`GET /sessions/{id}` 返回同样的精确值，同分片重试重放、失败不推进、
重启续判与多实例共用数据库后的比较基准均不受影响（对应 `tests/test_sequence_audit_wide.py`）。

#### 4.8 更换 SQLite 数据库：会话检查点导出 / 导入 / 续采

需要把服务换到一个**新的 SQLite 文件**（换库迁移、灾备重建、把会话搬到另一套环境）时，用两个
HTTP 接口把已有采集会话按**原 session_id** 整体搬到目标库，之后正常续采。导出读取的是**同一已提交
时刻**的快照：确切协议版本与定义摘要（SHA-256）、接收偏移、原始待决尾部、累计帧数、最近分片的
偏移/摘要与**原响应**，以及启用稽核时的序号稽核进度（含超出有符号 64 位的精确值）。

##### 4.8.1 从旧库导出检查点

```bash
# 旧库（RESYNC_DB_PATH=/data/resync.db，端口 8000）上已有会话
curl -s localhost:8000/sessions/00e49c0d66904047837921d05a3090d6/checkpoint -o /tmp/session-checkpoint.json
cat /tmp/session-checkpoint.json
```

```json
{
  "format_version": 1,
  "exported_at": "2026-10-07T08:30:00.000000+00:00",
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "protocol_id": "sensor-line",
  "version": 1,
  "definition_sha256": "9f2c…（导出时该协议版本在旧库中的定义摘要）",
  "received_offset": 17,
  "tail_b64": "qlUCAw==",
  "frames_total": 1,
  "last_chunk_offset": 0,
  "last_chunk_sha256": "…（第 1 片原始字节的 SHA-256）",
  "last_response": { … 与第 1 片追加响应逐字节相同（"replayed": false）… },
  "audit_enabled": false,
  "sequence_audit": null
}
```

- 从未追加过分片的会话也可导出：`received_offset`/`frames_total` 为 0，尾部与最近分片/响应均为空。
- 启用稽核的会话 `audit_enabled` 为 `true`，`sequence_audit` 携带 `bit_width`、`last_sequence`
  与各类累计值；这些值是精确整数，达到 2⁶⁴ 量级也不丢位（见 4.7.4）。
- 会话不存在返回 404 `SESSION_NOT_FOUND`。

##### 4.8.2 目标库先注册同一协议，再导入

目标库是全新数据库时，先像第 1 节那样注册**协议 ID 与确切版本完全相同、定义也完全相同**的协议
（可用 `GET /protocols` 核对 `definition_sha256`）。然后把检查点 POST 到目标库：

```bash
# 目标库（另一份 docker compose / 另一个 RESYNC_DB_PATH，端口 8001）
curl -s -X POST localhost:8001/sessions/import \
  -H 'Content-Type: application/json' \
  --data @/tmp/session-checkpoint.json
```

```json
{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "protocol_id": "sensor-line",
  "version": 1,
  "received_offset": 17,
  "next_offset": 17,
  "tail": {"start": 13, "end": 17, "payload_b64": "qlUCAw=="},
  "frames_total": 1,
  "last_chunk_offset": 0,
  "last_chunk_sha256": "…",
  "created_at": "2026-10-07 08:31:10",
  "updated_at": "2026-10-07 08:31:10"
}
```

导入只在以下条件**全部**满足时才接受，并且所有状态在**一个数据库事务内一次落库**：

1. 目标库已注册 `protocol_id` + 确切 `version`，且其 `definition_sha256` 与检查点**完全相同**；
2. 检查点启用序号稽核时，目标库该确切协议必须仍声明**有效无符号整数序号字段**（`u*` 类型且未置
   `signed`，位域按 `bit_width` 计、宽度 ≥2），且其**有效位宽与检查点的
   `sequence_audit.bit_width` 完全一致**（稽核模数必须等于目标协议序号字段位宽）；`last_sequence`
   等响应内携带的原始序号还必须落在该位宽的原始范围 `[0, 2^bit_width)` 内；
3. 目标库中**不存在**同一 `session_id` 的会话；
4. 检查点自洽：尾部可解码且不长于接收偏移；**最近响应的 `tail.start` 必须恰好等于接收偏移减去
   解码后尾部字节数**（续采起点，落在区间内但整体平移也拒绝）；最近响应的会话/协议标识、
   `next_offset`、尾部、`frames_total` 与检查点其余字段一致；最近分片偏移/摘要齐备（未追加过的空
   会话除外）；稽核块与 `audit_enabled` 一致且与最近响应中的稽核累计一致。

协议核验（定义摘要 + 序号字段/位宽）、同名会话检查与会话行写入在**同一个 `BEGIN IMMEDIATE` 写事务**
内完成：并发的协议注册（或另一进程上的竞争导入）只能在该事务结束后提交，无法在核验与写入之间替换
协议定义或凭空注册协议来绕过核验。

任何一条不满足，**整次导入失败、目标库不写任何内容、也不覆盖现有状态**：

| HTTP | code | details.reason / 说明 |
| --- | --- | --- |
| 422 | `SESSION_IMPORT_INVALID` | `protocol_mismatch`：目标库未注册该确切版本，或已注册但定义摘要不同 |
| 422 | `SESSION_IMPORT_INVALID` | `audit_mismatch`：检查点稽核位宽与目标协议序号字段的有效位宽不符，或目标协议无可用的无符号序号字段（附 `checkpoint_bit_width` / `target_bit_width`） |
| 422 | `SESSION_IMPORT_INVALID` | `details.problems`：检查点格式版本不支持、字段缺失/越界、`tail.start` 与接收偏移/尾部字节数不符、序号超出位宽基准范围、最近响应/稽核不自洽 |
| 409 | `SESSION_IMPORT_CONFLICT` | `session_exists`：目标库已有同名会话，现有状态原样保留 |
| 422 | `INVALID_JSON` | 请求体不是合法 JSON |

因此可以安全重试：修正协议注册或检查点后重新 POST 即可；目标库已有该会话时重复导入只会得到
409，既有进度不会被覆盖。

畸形检查点（稽核模数被篡改、尾部起点平移）会原样返回 422 `SESSION_IMPORT_INVALID`，整次不落库：

```bash
# 例 1：目标协议的 seq 是 u8（有效位宽 8），检查点却把稽核模数改成 2
#        （顶层 sequence_audit.bit_width 与 last_response 内同步改为 2）
jq '.sequence_audit.bit_width = 2
    | .last_response.sequence_audit.bit_width = 2' /tmp/session-checkpoint.json \
  | curl -s -X POST localhost:8001/sessions/import \
      -H 'Content-Type: application/json' --data @-
# -> 422 {"error": {"code": "SESSION_IMPORT_INVALID",
#        "message": "…",
#        "details": {"reason": "audit_mismatch",
#                    "checkpoint_bit_width": 2, "target_bit_width": 8, …}}}

# 例 2：last_response.tail.start 被改小（仍不超过 tail.end，但不等于
#        received_offset - 解码后尾部字节数）
jq '.last_response.tail.start -= 1' /tmp/session-checkpoint.json \
  | curl -s -X POST localhost:8001/sessions/import \
      -H 'Content-Type: application/json' --data @-
# -> 422 {"error": {"code": "SESSION_IMPORT_INVALID",
#        "details": {"problems": ["…tail.start does not equal received_offset
#                                 minus the decoded tail byte count …"]}}}
```

两种情况下目标库都不会写入该会话（随后用未篡改的检查点重新导入即可成功）；若目标库已有同名会话，
则无论检查点内容如何都返回 409 `SESSION_IMPORT_CONFLICT`，现有状态不变。

##### 4.8.3 导入后重放最近分片并跨片续采

导入后先按 `last_chunk_offset` 把**最近一个分片原样重发**，服务返回存档的原响应（`replayed: true`），
不重复产出帧、`frames_total` 不变；随后用 `next_offset` 继续发新分片——被迁移边界拆开的帧
（上例尾部 `aa 55 02 03`）会在目标库补齐，偏移仍是原会话的累计位置，序号稽核也从导入的基准
与累计值继续：

```bash
# 1) 重放最近分片（内容与旧库第 1 片完全相同）-> 原响应，replayed=true，frames_total 仍为 1
curl -s -X POST localhost:8001/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 0,
  "chunk_b64": "EjSqVQEDCSkJAHWbAKpVAgM="
}'

# 2) 用旧库时的 next_offset=17 续发第 2 片 -> 帧 2 在累计偏移 [13,24) 补齐，frames_total=2
curl -s -X POST localhost:8001/sessions/append -H 'Content-Type: application/json' -d '{
  "session_id": "00e49c0d66904047837921d05a3090d6",
  "expected_offset": 17,
  "chunk_b64": "/2oJAKqKAA=="
}'
```

启用稽核的会话同样无缝接续：导入后下一帧相对导入的 `last_sequence` 判定，各类异常计数与
`missing_total` 在导入值上累加；即使基准序号或累计缺失数超过 SQLite 有符号整数范围
（2⁶³ − 1），导入与后续追加仍以十进制文本逐位精确保存。两个独立数据库间的完整导出/导入/续采
往返（含跨片解码、原响应重放不重复计数、宽稽核值、协议不匹配/同名会话/被篡改检查点拒绝且不
覆盖）对应 `tests/test_session_checkpoints.py`。

## 协议声明字段

| 字段 | 说明 |
| --- | --- |
| `sync` | 1–8 个同步字节（如 `[0xAA,0x55]`） |
| `endian` | 协议默认端序 `big` / `little`；长度字段、CRC、各字段可单独覆盖 |
| `length_field` | `offset`（相对逻辑体）、`size`（1/2/4）、`endian`、`adjustment`。线上长度值 + adjustment = 逻辑帧长；当长度字段把帧头也计数时用负数（如 `-4`） |
| `escaping` | DLE 转义：`escape_byte`、`xor_mask`（转义后字节 = 原字节 XOR mask）、`escapes_sync`、额外受保护字节 `escaped_bytes` |
| `crc` | CRC-16 参数与 `offset`（2 字节 CRC 在逻辑体中的偏移）、`endian`、`verify` |
| `fields[]` | `type` 为 `u8/u16/u24/u32/u64/s8/s16/s24/s32/s64`；定点值 = 整数 × `scale` ÷ `divisor`；可选 `bit_offset`+`bit_width` 取位域，`min`/`max` 做范围校验 |
| `sequence_field` | 指定作为帧序号的字段名（响应中的 `sequence`） |
| `min/max_frame_length` | 逻辑帧长上下界；越界候选触发重同步 |

### 转义语义

转义只作用于同步头之间。开启后，同步字节、转义字节（及 `escaped_bytes` 声明的字节）
在链路上以 `escape_byte || (byte XOR xor_mask)` 两个字节出现；解码时实时反转义，长度
字段与所有字段偏移都按**逻辑（反转义后）空间**解释。缓冲区恰好结束在转义引导字节处时
视为不完整帧，进入 `tail`。

## 错误信封

所有错误统一为：

```json
{"error": {"code": "FIELD_OUT_OF_BOUNDS", "message": "…", "details": { … }}}
```

| HTTP | code | 触发场景 |
| --- | --- | --- |
| 422 | `VALIDATION_ERROR` / `INVALID_PROTOCOL` | 请求体或协议声明不合法（附字段级 details） |
| 422 | `INVALID_BASE64` | `payload_b64` 不是合法 base64 |
| 422 | `FIELD_OUT_OF_BOUNDS` | 字段超出帧边界，或缩放后值超出 `min/max` |
| 422 | `AMBIGUOUS_FRAME` | 多个不同起点的合法帧结束于同一位置 |
| 422 | `VALUE_NOT_REPRESENTABLE` | `/encode`：反算结果不是精确整数（或值非有限值、scale 为 0） |
| 422 | `UNKNOWN_FIELD` | `/encode`：请求的字段名不在协议声明中 |
| 422 | `OVERLAPPING_WRITE_CONFLICT` | `/encode`：字段覆盖同一比特但写入不同值 |
| 422 | `DERIVED_POSITION_CONFLICT` | `/encode`：字段占用长度字段或 CRC 的字节位置 |
| 422 | `LENGTH_NOT_ENCODABLE` | `/encode`：长度值超出长度字段位宽 |
| 422 | `ENCODE_VERIFICATION_FAILED` | `/encode`：解码器回读结果与请求不一致（帧拒绝返回） |
| 404 | `PROTOCOL_NOT_FOUND` | 协议 ID / 版本不存在 |
| 409 | `PROTOCOL_VERSION_CONFLICT` | 同 ID+版本已存在但定义不同 |
| 404 | `SESSION_NOT_FOUND` | 会话 ID 不存在（追加或进度查询） |
| 409 | `SESSION_APPEND_CONFLICT` | 会话追加：同偏移不同内容（`reason=content_mismatch`）或乱序/跳跃/并发提交（`reason=offset_mismatch`），状态不变 |
| 422 | `SEQUENCE_AUDIT_UNSUPPORTED` | 创建会话时启用了序号稽核，但协议未声明有效位宽 ≥2 的无符号整数序号字段 |
| 422 | `SESSION_IMPORT_INVALID` | 会话检查点导入：目标库未注册摘要相同的确切协议版本（`reason=protocol_mismatch`）、检查点稽核位宽与目标协议序号字段有效位宽不符（`reason=audit_mismatch`），或检查点格式/自洽性校验失败（含 `tail.start` 与接收偏移减尾部字节数不符、序号超出位宽基准范围；`details.problems`） |
| 409 | `SESSION_IMPORT_CONFLICT` | 会话检查点导入：目标库已存在同 `session_id` 的会话（`reason=session_exists`），不覆盖现有状态 |
| 413 | `PAYLOAD_TOO_LARGE` | 超 `RESYNC_MAX_DECODE_BYTES`（会话中指 待决尾部 + 新分片 的拼合大小） |

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `POST` | `/protocols` | 注册（或幂等覆盖）协议版本 |
| `GET` | `/protocols` | 列出已注册协议及定义摘要 |
| `GET` | `/protocols/{id}?version=N` | 读取协议定义（省略版本取最新） |
| `POST` | `/decode` | 解码 / 重同步 |
| `POST` | `/encode` | 按已注册协议编码一帧（长度/CRC/转义/同步自动生成，回读校验） |
| `POST` | `/sessions` | 创建分批采集会话（固定协议的确切版本；可选 `sequence_audit` 启用序号稽核） |
| `POST` | `/sessions/append` | 追加非空 base64 分片（尾部自动拼接，仅返回本次新结果与本次稽核异常） |
| `GET` | `/sessions/{id}` | 查询会话进度（偏移/待决尾部/累计帧数/最近一次分片/稽核累计） |
| `GET` | `/sessions/{id}/checkpoint` | 导出会话检查点（同一已提交时刻的协议摘要/偏移/尾部/帧数/最近分片与原响应/稽核进度），供换库导入 |
| `POST` | `/sessions/import` | 导入会话检查点到目标库（要求确切协议版本且定义摘要相同、稽核位宽与目标协议序号字段一致、尾部起点与接收偏移/尾部字节数相符、无同名会话、检查点自洽，协议核验与会话写入在同一写事务内一次落库） |

同 ID + 版本重复提交**完全相同**的定义是幂等的（返回 `replaced=true`）；定义不同则 409。

## 项目结构

```
app/
  config.py    # 环境配置
  models.py    # Pydantic 协议/请求/响应模型与协议自检
  crc.py       # 通用 CRC-16（反射/非反射）
  decoder.py   # 候选扫描、反转义、长度/CRC 校验、重同步与歧义判定
  encoder.py   # 字段写入（位域/定点反算/冲突检测）、长度与 CRC 派生、转义、回读校验
  audit.py     # 会话序号连续性稽核（取模比较、异常分类、基准推进）
  checkpoint.py # 会话检查点信封的自洽性校验（尾部起点/序号基准范围/最近响应，换库导出/导入）
  db.py        # SQLite：协议表 + (协议版本, 输入摘要) 结果缓存 + 采集会话状态表（含稽核列、检查点导入）
  errors.py    # 结构化错误类型
  main.py      # FastAPI 路由与错误处理（/decode、/encode、/sessions[/append]、检查点导出/导入）
tests/         # pytest 用例（含构造 CRC 碰撞的歧义用例、编码回读校验、会话跨分片/重试/重启、序号稽核、换库检查点）
Dockerfile
docker-compose.yml
```

## 测试

```bash
pip install -r requirements.txt pytest httpx
pytest
```

覆盖：半帧起始 + 噪声 + 多帧 + 不完整尾部、坏 CRC / 长度越界后重同步、DLE 转义
（含同步字节与转义字节被转义）、little-endian + CRC-16/MODBUS + 长度 adjustment、
位域与有符号定点缩放、字段越界 422、CRC 碰撞歧义 422、缓存复用、版本冲突与解析；
编码侧覆盖：定点精确反算、正负有符号值、位域共享字节与同值重叠、转义帧往返、
LE/adjustment 长度值、不可精确表示 / min/max / 位宽 / 派生位置 / 长度溢出 422，
以及解码器回读不一致拒绝返回。
会话侧（`tests/test_sessions.py`）覆盖：版本固定与缺失版本 404、跨分片（含跨片同步头、
dangling 转义符）只产出一次且偏移为累计位置、最近分片同偏移同内容重放不重复计数、同偏移异
内容 / 乱序跳跃 / 并发竞争 409 且不改状态、拼合超限与歧义硬错不推进偏移、空/非法分片 422，
以及关闭并重建 App（模拟服务重启）后进度/尾部持久化、重放原响应并继续追加。
`tests/test_sessions_multi_instance.py` 用两个共享同一 SQLite 文件的独立实例核对：不同分片
同偏移竞争恰有一个提交、落败方 409 `content_mismatch` 且状态只反映胜方；相同分片竞争一个
提交一个重放、不重复计帧；活跃实例间交替追加与进度互见；新实例（模拟重启）读取进度、重放
最近分片并继续追加。
`tests/test_sessions_migration_concurrency.py` 定向覆盖旧库升级的并发与失败路径：两个 OS 进程
同时启动并打开同一旧库（稽核列尚不存在的前稽核库、宽列仍为 INTEGER 的稽核时代库）时，一个实例
执行补列/TEXT 重建，另一个等待写锁后重新判断结构并放行，双方启动均成功且无重复列/残留临时表；
确定性用例核对后到实例在锁释放前阻塞、释放后不再发任何补列或重建语句；重建中途注入故障时事务
整体回滚（原表、INTEGER 列与全部历史行保留、无临时表残留），再次启动重试完成；升级后两个实例
都能查询历史会话、重放迁移前最近分片，并跨实例继续追加到超过有符号 64 位范围的最近序号与累计
缺失数且数值逐位精确。
`tests/test_sequence_audit.py` 覆盖序号稽核：创建门控（未声明/有符号/位宽不足均 422，恰好
2 位可建）、未启用会话行为不变、重复/疑似缺帧（含缺失数量与回绕取模）/倒退/恰好半圈无法判向
的分类、每个有效帧重设基准、坏帧与未决尾部不动基准、位域序号按 `bit_width` 取模、重试重放
稽核区块不重复计数、409/422 不动稽核状态、重启后从持久化基准续判、进度累计各类异常次数、
旧库文件就地迁移后老会话照常使用，以及多实例竞争下异常只计一次。
`tests/test_sequence_audit_wide.py` 覆盖 u64 边界：原始序号达到 2⁶³ 与 2⁶⁴−1 时追加成功且
异常明细/字节偏移/累计计数逐位精确、依次确认 0、2⁶³−1、0、2⁶³−1 时累计缺失数达 2⁶⁴−4 仍精确、
恰好半圈（2⁶³）判 `indeterminate`、宽值重试重放不重复计数、409/413 不推进宽基准、重启与多实例
共用数据库后从持久化宽基准续判、宽审计列仍为 INTEGER 的旧库就地重建为 TEXT 后历史值不变且可
继续写入超大序号，以及未启用稽核会话与无状态 `/decode` 对同样宽序号的行为保持不变。
`tests/test_session_checkpoints.py` 覆盖换库检查点：导出包含同一已提交时刻的协议定义摘要、偏移、
原始尾部、累计帧数、最近分片摘要与原响应及稽核进度（含未追加的空会话）；目标库缺协议/定义摘要
不同/稽核位宽与目标协议序号字段不一致（8 位被篡改为 2 位等，含只改顶层模数的结构性拒绝）/序号基准
超出位宽范围/已有同名会话分别 422（`protocol_mismatch` / `audit_mismatch` / `details.problems`）
与 409 `session_exists` 且不写不覆盖；`tail.start` 不等于接收偏移减解码尾部字节数（即使未越过
`tail.end`）一律 422；并发协议注册在导入写事务持锁期间阻塞、不能绕过核验；导入后最近分片重放
返回原响应（`replayed`）不重复计数、跨分片帧在原累计位置补齐、稽核按正确模数从导入基准与累计值
续判、超过 2⁶³ 的宽稽核值在目标库仍以精确十进制文本保存，以及导入状态在目标服务重启后照常重放
与续采。
