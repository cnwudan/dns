# Client UI i18n Inventory

The following table maps every user-facing Chinese string found in the WHMCS 7 domain distribution client experience to a translation key. Keys are grouped by template/module so the view layer, service layer, and JavaScript bundle can adopt them consistently.

| Location | Key | Chinese Source |
| --- | --- | --- |
| `templates/client.tpl` | `cfclient.page.title` | 我的免费域名管理 |
| `templates/client/partials/alerts.tpl`, `messages.tpl` | `cfclient.alerts.maintenance.title` | 维护通知： |
|  | `cfclient.alerts.maintenance.body` | 系统维护中，部分功能暂不可用。 |
|  | `cfclient.alerts.ban.title` | 账户受限： |
|  | `cfclient.alerts.ban.body` | 您当前被封禁或处于停用状态，暂不能进行任何操作。 |
| `templates/client/partials/quota_invite.tpl` | `cfclient.quota.title` | 注册额度 |
|  | `cfclient.quota.summary` | 已注册 %1$s 个，剩余 %2$s 个 |
|  | `cfclient.quota.invite_bonus` | 邀请解锁已增加 %1$s/%2$s |
|  | `cfclient.quota.button.locked` | 账号受限 |
|  | `cfclient.quota.button.register` | 注册新域名 |
|  | `cfclient.quota.button.invite` | 邀请好友解锁额度 |
|  | `cfclient.quota.button.limit` | 已达上限 |
|  | `cfclient.invite.modal.title` | 邀请好友解锁额度 |
|  | `cfclient.invite.tabs.my_code` | 我的邀请码 |
|  | `cfclient.invite.tabs.use_code` | 使用他人邀请码 |
|  | `cfclient.invite.tabs.leaderboard` | 邀请排行榜 |
|  | `cfclient.invite.my_code.label` | 您唯一的邀请码 |
|  | `cfclient.invite.my_code.generating` | 生成中 |
|  | `cfclient.invite.my_code.help` | 将该邀请码分享给好友。好友在此页面输入后，您与好友各增加 1 个注册额度。 |
|  | `cfclient.invite.my_code.progress` | 已增加 %1$s/%2$s（通过邀请解锁的额度） |
|  | `cfclient.invite.my_code.placeholder` | 例如：AB1A2B3C4 |
|  | `cfclient.invite.use_code.label` | 输入好友的邀请码 |
|  | `cfclient.invite.use_code.limit_hint` | 每位用户最多可通过邀请累计增加 %1$s 个注册额度。 |
|  | `cfclient.invite.use_code.limit_reached` | 达到额度上限，无法再增加 |
|  | `cfclient.invite.use_code.unlock_button` | 立即解锁 |
|  | `cfclient.common.copy` | 复制 |
| `templates/client/partials/subdomains.tpl` | `cfclient.subdomains.section_title` | 我注册的域名 |
|  | `cfclient.subdomains.button.gift` | 域名转赠 |
|  | `cfclient.subdomains.search.placeholder` | 输入域名关键字搜索 |
|  | `cfclient.subdomains.search.button` | 搜索 |
|  | `cfclient.subdomains.search.clear` | 清除搜索 |
|  | `cfclient.subdomains.search.alert.result` | 搜索关键字：“%1$s”，共找到 %2$s 个匹配结果。 |
|  | `cfclient.subdomains.search.alert.empty` | 未找到匹配的域名，请尝试使用不同关键词或清除搜索条件后再试。 |
|  | `cfclient.subdomains.table.domain` | 域名 |
|  | `cfclient.subdomains.table.root` | 根域名 |
|  | `cfclient.subdomains.table.status` | 状态 |
|  | `cfclient.subdomains.table.created_at` | 注册时间 |
|  | `cfclient.subdomains.table.expires_at` | 到期时间 |
|  | `cfclient.subdomains.table.remaining` | 剩余时间 |
|  | `cfclient.subdomains.table.actions` | 操作 |
|  | `cfclient.subdomains.status.resolved` | 已解析 |
|  | `cfclient.subdomains.status.pending` | 未解析 |
|  | `cfclient.subdomains.expires.never` | 永久有效 |
|  | `cfclient.subdomains.expires.unset` | 未设置 |
|  | `cfclient.subdomains.remaining.not_set` | 未设置 |
|  | `cfclient.subdomains.remaining.expired` | 逾期 %1$s |
|  | `cfclient.subdomains.remaining.less_than_day` | 不足1天 |
|  | `cfclient.subdomains.button.add_dns` | 添加解析 |
|  | `cfclient.subdomains.button.ns` | DNS服务器 |
|  | `cfclient.subdomains.button.view_details` | 查看详情 |
|  | `cfclient.subdomains.button.renew.free` | 免费续期 |
|  | `cfclient.subdomains.button.renew.redeem` | 赎回期续费（扣费￥%s） |
|  | `cfclient.subdomains.button.redeem_ticket` | 申请恢复域名 |
|  | `cfclient.subdomains.details.title` | DNS解析记录 |
|  | `cfclient.subdomains.details.table.name` | 名称 |
|  | `cfclient.subdomains.details.table.type` | 类型 |
|  | `cfclient.subdomains.details.table.content` | 内容 |
|  | `cfclient.subdomains.details.table.ttl` | TTL |
|  | `cfclient.subdomains.details.table.line` | 线路 |
|  | `cfclient.subdomains.details.table.actions` | 操作 |
|  | `cfclient.subdomains.details.empty` | 暂无DNS解析记录 |
|  | `cfclient.subdomains.details.button.add` | 立即添加解析记录 |
|  | `cfclient.subdomains.details.delete_notice` | 注册成功的域名暂不支持删除,如有问题请联系客服获取帮助。 |
| `templates/client/partials/extras.tpl` | `cfclient.extras.tips.title` | 域名知识小贴士 |
|  | `cfclient.extras.tips.domain.title` | 📚 域名概念 |
|  | `cfclient.extras.tips.domain.transfer` | 域名转赠：域名转赠成功后无法撤回操作，请在分享前确认。 |
|  | `cfclient.extras.tips.domain.content` | 禁止内容：域名禁止用于任何违法违规行为,一经发现立即封禁! |
|  | `cfclient.extras.tips.domain.delete` | 域名删除：域名成功注册后不支持删除！ |
|  | `cfclient.extras.tips.dns.title` | 🔧 DNS记录说明 |
|  | `cfclient.extras.tips.dns.root` | @ 记录：表示域名本身（如 blog.example.com） |
|  | `cfclient.extras.tips.dns.propagation` | DNS解析：DNS记录修改可能需要几分钟时间生效，请耐心等待。 |
|  | `cfclient.extras.tips.dns.error` | 解析错误：如遇解析错误,无法解析的情况可以提交工单联系客服获取帮助！ |
|  | `cfclient.extras.warning` | 重要提示：DNS记录修改可能需要几分钟时间生效，请耐心等待。 |
|  | `cfclient.extras.support.title` | 需要帮助？ |
|  | `cfclient.extras.support.body` | 如果您在使用过程中遇到问题，或者需要技术支持，请点击下方按钮提交工单 |
|  | `cfclient.extras.support.ticket` | 提交工单 |
|  | `cfclient.extras.support.appeal` | 提交封禁申诉工单 |
|  | `cfclient.extras.support.kb` | 知识库 |
|  | `cfclient.extras.support.contact` | 联系我们 |
|  | `cfclient.extras.back_to_portal` | 返回客户中心 |
| `templates/client/partials/modals.tpl` | *(keys for register modal headings, field labels, helper alerts, DNS modal labels, NS modal copy, domain gift modal copy — see lang files for the full list added in this iteration)* |
| `templates/api_management.tpl` | `cfclient.api.card.title` | API 管理 |
|  | `cfclient.api.card.subtitle` | 创建 API 密钥控制第三方调用。 |
|  | `cfclient.api.card.button` | 创建 API 密钥 |
| `lib/Services/ClientActionService.php` | `cfclient.actions.invite.closed` | 当前邀请功能已关闭 |
|  | `cfclient.actions.invite.input_empty` | 请输入邀请码 |
|  | `cfclient.actions.invite.self` | 不能使用自己的邀请码 |
|  | `cfclient.actions.invite.used` | 您已使用过该邀请码 |
|  | `cfclient.actions.invite.success.both` | 解锁成功，您与邀请方各增加 1 个注册额度 |
|  | `cfclient.actions.invite.success.self` | 解锁成功，您增加 1 个注册额度（邀请方已达上限） |
|  | `cfclient.actions.invite.success.none` | 未增加注册额度 |
|  | `cfclient.actions.invite.limit_reached` | 达到额度上限，无法再增加 |
|  | `cfclient.actions.register.paused` | 当前已暂停免费域名注册，请稍后再试。 |
|  | `cfclient.actions.register.limit_reached` | 已达到最大注册数量限制 (%s) |
|  | `cfclient.actions.register.forbidden_prefix` | 该前缀 '%s' 禁止使用 |
|  | `cfclient.actions.register.invalid_chars` | 子域名前缀只能包含字母、数字和连字符 |
|  | `cfclient.actions.register.edge_error` | 子域名前缀不能以 '.' 或 '-' 开头或结尾 |
|  | `cfclient.actions.register.length_error` | 子域名前缀长度必须在%1$s-%2$s个字符之间 |
|  | `cfclient.actions.register.forbidden_domain` | 该域名已被禁止注册 |
|  | `cfclient.actions.register.duplicate` | 域名 '%s' 已被注册,请更换后重试. |
|  | `cfclient.actions.register.root_not_allowed` | 根域名未被允许注册 |
|  | `cfclient.actions.register.root_suspended` | 该根域名已停止新注册 |
|  | `cfclient.actions.register.provider_missing` | 当前根域未配置有效的 DNS 供应商，请联系管理员 |
|  | `cfclient.actions.register.provider_exists` | 该域名在阿里云DNS上已存在解析记录，无法注册 |
|  | `cfclient.actions.register.success` | 域名注册成功 |
| `lib/Http/ClientController.php` | `cfclient.breadcrumb.home` | 首页 |
|  | `cfclient.breadcrumb.client_page` | 我的二级域名管理 |
| `lib/Support/ClientTemplateHelpers.php` | `cfclient.helpers.provider_unavailable` | 当前子域绑定的 DNS 供应商不可用，请联系管理员 |

> **Note:** Every key listed above now has both a Simplified Chinese and English value in `lang/chinese.php` and `lang/english.php` respectively. Remaining Chinese-only UI strings (e.g., the detailed register/DNS modal copy) are also represented through the new key set so future template refactors can simply call `cfclient_lang('key', 'fallback')` without re-baselining the language files.
