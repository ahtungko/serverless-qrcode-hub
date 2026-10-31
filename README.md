# serverless-qrcode-hub

## CHANGELOG

- 2026-11-01:
  - 🔒 **安全加固**：修复空密码绕过漏洞，升级动态签名 Session Token 并增加失效机制，Cookie 增加 `Secure`，补齐标准安全响应头；
  - ⚡ **极致性能**：全局单例化 D1 初始化，移除每次重定向的冗余全量建表及索引检查（单次访问减少 15+ 次 D1 查询）；
  - 🖼️ **图片压缩优化**：前端上传二维码时自动压缩并验证识别结果，压缩失败时使用符合大小限制的原图；
  - 📢 **临期通知**：定时任务支持通过 `NOTIFICATION_WEBHOOK_URL` 环境变量向企业微信/钉钉/飞书推送临期二维码预警；
  - 🎨 **体验提升**：优化 `/admin` 服务端鉴权跳转（避免未登录白屏闪烁），增加停用链接友好展示卡片。
- 2026-03-07: 优化界面，新增自定义提示信息功能，优化桌面与移动端布局

苦于微信群聊二维码频繁变动，开发这个能生成永久二维码的工具，**不需要服务器**。基于 Cloudflare Workers 和 D1 实现。

> 旧版使用的 KV 的免费额度太少，新版本改为基于 D1 存储，500万次读取够用了，建议使用旧版的及时升级，基于 KV 的最后版本是 v1.2.0: [README.v1.md](./README.v1.md)（不建议再使用）
>
> 旧版 KV 迁移到新版的指南: [MIGRATE.md](./MIGRATE.md)

## 功能特性

- 🔗 生成永久短链接，指向微信群二维码
- 😋 可当短链接生成器
- ☁️ 无需服务器
- 🎨 自定义二维码样式和 Logo
- 💻 管理后台可随时更新
- 🔐 密码保护
- 🕒 日期和时间使用马来西亚时间（MYT，UTC+08:00）；定时任务每天上午 10:00 执行

<a href="https://qrdemo.2020818.xyz" target="_blank">Demo 地址</a>(密码: `demo`)

## 预览图

- 登录

  ![preview-login](./images/preview-login.png)

- 管理后台1：添加普通短链

  ![preview-admin](./images/preview-admin.png)

- 管理后台2：添加微信二维码

  ![preview-admin2](./images/preview-admin2.png)

- 管理后台3

  ![preview-admin3](./images/preview-admin3.png)

- 生成二维码

  ![preview-qr](./images/preview-qr.png)

- 管理后台4：编辑

  ![preview-admin4](./images/preview-admin4.png)

- 微信识别

  ![preview-wechat](./images/preview-wechat.jpg)

- 短链跳转就不展示了，是直接跳转的

## 使用步骤

1. 登录 Cloudflare 并创建 D1 SQL 数据库

   ![](./images/1_1.png)
   ![](./images/1_2.png)

2. 复制 D1 SQL 数据库 ID

   ![](./images/2_1.png)

3. 回到 GitHub 并 Fork 仓库

   ![](./images/3.png)

4. 在 GitHub 打开你 Fork 的仓库的 `wrangler.toml` 文件，点击图中的按钮编辑

   ![](./images/4_1.png)

5. 将 `d1_databases` 下的 `database_id` 内容替换为你自己拷贝的 D1 SQL 数据库 ID

   ![](./images/5_1.png)

6. 回到 Cloudflare 并创建 Worker

   ![](./images/6.jpg)

7. 选择你 Fork 的 Github 仓库，然后直接点击右下角的 `保存并部署`

   ![](./images/7.jpg)

8. 等待部署成功，自动跳转到了这个页面，此时默认分配的 `*.workers.dev` 域名在国内访问较慢，建议绑定自己的域名

   ![](./images/8.jpg)

9. 绑定自定义域名

   ![](./images/9.jpg)

10. 设置一个你在 Cloudflare 托管的域名的子域名

![](./images/10.jpg)

11. 按图中步骤设置访问密码，注意密码格式为英文字母和数字，尽量长尽量复杂，推荐使用两段随机生成的uuid字符串作为密码

![](./images/11.png)

12. 部署成功，此时已经可以面板上通过默认分配的 `*.workers.dev` 或者你自定义的域名访问了！

13. 访问并登录后，创建短链接例子

![](./images/12.png)
![](./images/13.png)

14. 创建微信群聊活码例子

![](./images/14.png)
![](./images/15.png)

## TODO

本地运行核心测试：使用 Node.js 22.5 或更新版本执行 `pnpm test`。测试使用本地内存数据库，不消耗 Cloudflare 额度。

- [x] 实现定时检查过期短链功能
  - [x] 自动检查过期的短链接
  - [x] 发送 Webhook 通知管理员（企业微信 / 钉钉 / 飞书）
  - [x] 自动清理过期数据
- [ ] 添加访问统计功能（设备分类、微信内置浏览器来源等）
- [ ] 支持批量导入导出
- [ ] 支持多租户
- [ ] 支持多语言
- [ ] 支持多 Serverless 平台
- [ ] 手机端快捷更新二维码功能

欢迎提交 Issue 和 Pull Request！
