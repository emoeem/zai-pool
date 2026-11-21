"""billing — Z.ai Coding Plan 额度子系统（Phase 5 独立化）。

与 HTTP 主网关彻底解耦：查询/领取失败不影响 API 转发。
上游：zcode.z.ai/api/v1/zcode-plan（billing 域，JWT+device_mid 鉴权）。

安全边界（计划书 5.4-5.6）：
- auto_claim 默认关闭；领取走状态机 pending→previewed→claiming→
  success/already/failed→verified，HTTP 200 不等于成功，需业务码+回查确认。
- 未知响应结构一律 failed，绝不误判 already/success。
- 账本只记账号名/计划/结果/原因，永不落 JWT。
- 不同 unit_type 的额度不混合计算（policy 按条目处理）。
"""
from billing.adapter import BillingAdapter  # noqa: F401
from billing.models import Balance, ClaimOutcome  # noqa: F401
