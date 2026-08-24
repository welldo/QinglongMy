# QinglongMy

自用青龙脚本库，抓取特定数据处理。将结果格式化为 Markdown 文本后通过机器人发送通知

| [Server酱(微信服务号) ](https://sct.ftqq.com/sendkey/r/14730) | [PushMe(App)](https://push.i-i.me/) |             钉钉机器人              |
|:-------------------------------------------------------:|:-----------------------------------:|:------------------------------:|
|             ![](screenshots/preview-1.jpg)              |   ![](screenshots/preview-2.jpg)    | ![](screenshots/preview-5.jpg) |
|             ![](screenshots/preview-4.jpg)              |   ![](screenshots/preview-3.jpg)    |                                |

## 功能

* [epic_free_game](epic_free_game.py) Epic每周限免信息
* [stock_spider](stock_spider.py) 获取股票、指数行情数据推送到微信，支持实时查看行情
* [trade_notify](trade_notify.py) 监控指定股票的行情，并在满足特定条件时发送通知，提醒买入或卖出时机
* [weibo_summary](weibo_summary.py) 抓取微博热搜榜，Sqlite数据库去重，过滤一些不感兴趣的内容，简单的词频分析
* [send_qq_email](send_qq_email.py) 发送带附件的电子邮件
* [job_spider](job_spider.py) 指定过滤条件获取远程工作信息
* [xb](xb.py) 全网羊毛线报精选，使用 gemini-3-flash-preview 模型进行内容分析
* [douban_spider](douban_spider.py) 豆瓣小组（上海租房版demo）
* [workbuddy_checkin](workbuddy_checkin.py) WorkBuddy 每日积分自动签到（100积分/天，连续第7天1000积分），自动读取本机登录态，幂等可重复运行
* [trae_checkin](trae_checkin.py) Trae Work 每日积分自动签到，自动解密本机 Trae 桌面端登录态（AES-128-CBC 信封），`--export-env` 可导出环境变量供青龙部署
* [minimax_checkin](minimax_checkin.py) MiniMax Code 每日积分自动签到（400积分/天，第4、7天1000积分），自动读取本机 MiniMax Agent 桌面端登录态（JWT），逆向 `yy`/`x-signature` 签名，`--export-env` 可导出环境变量供青龙部署
* [checkin_all](checkin_all.py) 聚合签到（推荐）：**只需设一个定时**，依次跑 WorkBuddy / Trae Work / MiniMax Code 三个签到，合并结果后**只发一次推送**。各子脚本的单独定时可停用/删除

## 安装依赖库

   ```shell
   pip3 install -r requirements.txt
   ```

## 添加仓库

   ```shell
   ql repo https://github.com/mgmg22/QinglongMy.git "summary|stock_spider|trade|epic_free_game|xb|send_qq|job|checkin" "activity|backUp" "sendNotify|stopwords|util" "main"
   ```

## 推送渠道及在线测试

[Server酱](https://sct.ftqq.com/sendkey/r/14730)(每天5条免费推送额度)

[PushMe](https://push.i-i.me/)

[Gemini API密钥](https://aistudio.google.com/app/apikey)

钉钉群机器人

## 配置文件

```shell
## ql repo命令拉取脚本时需要拉取的文件后缀，直接写文件后缀名即可
RepoFileExtensions="js py txt"

# server酱的 PUSH_KEY
export PUSH_KEY_MY=
export PUSH_KEY_SECOND=

## PushMe key
export PUSH_ME_KEY=
## 邮箱地址和smtp密钥
export EMAIL_ADDRESS=
export EMAIL_PWD=

## 钉钉机器人key
export XB_BOT_TOKEN=
export JOB_BOT_TOKEN=

## Gemini API密钥和API域名
export API_KEY=
export API_URL=

## WorkBuddy 每日签到（workbuddy_checkin.py）
# 留空时自动读取本机 WorkBuddy 桌面端(v5.3.8+)明文登录态；跨机/容器部署时手动填写
export WB_ACCESS_TOKEN=
export WB_USER_ID=
# 可选：domain 一般留空自动读取
export WB_DOMAIN=

## Trae Work 每日签到（trae_checkin.py）
# 留空时自动解密本机 Trae 桌面端登录态并提取数字设备 id（%APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json）
#   - 设备 id 取 storage.json 中 iCubeAuthInfo://icube-dc:<numeric> 键的数字部分；服务端按注册指纹校验 device id，
#     UUID 格式的 telemetry.devDeviceId 不被识别为注册设备，会触发更严格限流（sign 接口 code 9074）
#   - 跨机/容器部署时，在本机执行 `python trae_checkin.py --export-env` 导出后填入
#     （token 约10天过期需重新导出；设备 id 已自动导出为正确的数字值，切勿填 UUID）
export TRAE_TOKEN=
export TRAE_DEVICE_ID=
export TRAE_HOST=

## MiniMax Code 每日签到（minimax_checkin.py）
# 留空时自动读取本机 MiniMax Agent 桌面端登录态（%APPDATA%\MiniMax Agent\minimax-agent-config.json -> tokens.accessToken）
#   - token 由客户端运行时刷新写回，默认跟随客户端有效（实测当前 token 有效期约至 2026-10）
#   - 跨机/容器部署时，在本机执行 `python minimax_checkin.py --export-env` 导出后填入
#     （token 过期后在 MiniMax Agent 客户端重新登录即可）
export MINIMAX_TOKEN=
export MINIMAX_USER_ID=
# 可选：同机稳定性参数，留空时自动生成并缓存在 .minimax_device.json
export MINIMAX_UUID=
export MINIMAX_DEVICE_ID=
# 可选：覆盖本机登录态配置文件路径（默认 %APPDATA%\MiniMax Agent\minimax-agent-config.json）
export MINIMAX_CONFIG_PATH=
   ```

若没有使用load_dotenv()，所有新增PUSH_KEY需要在[sendNotify](sendNotify.py)的push_config中配置key名称后才能生效

## 本地开发

复制 .env.example 为 .env 并填写配置


## Special statement:

* Any unlocking and decryption analysis scripts involved in the Script project released by this warehouse are only used
  for testing, learning and research, and are forbidden to be used for commercial purposes. Their legality, accuracy,
  completeness and effectiveness cannot be guaranteed. Please make your own judgment based on the situation. .

* All resource files in this project are forbidden to be reproduced or published in any form by any official account or
  self-media.

* This warehouse is not responsible for any script problems, including but not limited to any loss or damage caused by
  any script errors.

* Any user who indirectly uses the script, including but not limited to establishing a VPS or disseminating it when
  certain actions violate national/regional laws or related regulations, this warehouse is not responsible for any
  privacy leakage or other consequences caused by this.

* Do not use any content of the Script project for commercial or illegal purposes, otherwise you will be responsible for
  the consequences.

* If any unit or individual believes that the script of the project may be suspected of infringing on their rights, they
  should promptly notify and provide proof of identity and ownership. We will delete the relevant script after receiving
  the certification document.

* Anyone who views this item in any way or directly or indirectly uses any script of the Script item should read this
  statement carefully. This warehouse reserves the right to change or supplement this disclaimer at any time. Once you
  have used and copied any relevant scripts or rules of the Script project, you are deemed to have accepted this
  disclaimer.

**You must completely delete the above content from your computer or mobile phone within 24 hours after downloading.
**  </br>
>
***You have used or copied any script made by yourself in this warehouse, it is deemed to have accepted this statement,
please read it carefully*** 