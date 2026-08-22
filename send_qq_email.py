"""
cron: 00 15 1 * * 0  send_qq_email.py
new Env('qq邮件');
"""
import os
import markdown
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

sender = os.getenv('EMAIL_ADDRESS')
password = os.getenv('EMAIL_PWD')
receiver = sender
# 附件文件路径
attachment_path = 'xb.db'
smtp_server = 'smtp.qq.com'
smtp_port = 465


def generate_html_body():
    md_file_path = 'log_stock.md'
    with open(md_file_path, 'r', encoding='utf-8') as file:
        markdown_content = file.read()
    html_table = markdown.markdown(markdown_content, extensions=['tables'])
    return MIMEText(html_table, 'html', 'utf-8')


def generate_attachment():
    with open(attachment_path, 'rb') as attachment_file:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment_file.read())

    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment', filename=attachment_path)
    return part


def delete_db_files():
    """邮件发送成功后清理本地数据库文件。"""
    for path in (attachment_path, 'wb.db'):
        if os.path.exists(path):
            try:
                os.remove(path)
                print(f"{path} 已被删除。")
            except OSError as e:
                print(f"删除{path} 出错: {e}")


def build_message():
    msg = MIMEMultipart()
    msg['From'] = f' <{sender}>'
    msg['To'] = f' <{receiver}>'
    msg['Subject'] = f'本周收盘行情及{attachment_path}附件。'
    msg.attach(generate_html_body())
    msg.attach(generate_attachment())
    return msg


def main():
    if not sender or not password:
        print("未设置 EMAIL_ADDRESS / EMAIL_PWD，取消发送")
        return

    server = None
    try:
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.login(sender, password)
        msg = build_message()
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        print("邮件发送成功")
        delete_db_files()
    except smtplib.SMTPException as e:
        print("Error: 无法发送邮件", e)
    finally:
        if server is not None:
            server.quit()


if __name__ == "__main__":
    main()
