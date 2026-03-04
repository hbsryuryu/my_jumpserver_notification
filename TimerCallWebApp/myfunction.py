import os
from dotenv import load_dotenv
load_dotenv(override=True)

WORKSPACE_ID = os.environ["WORKSPACE_ID"]
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL_ID = os.environ["SLACK_CHANNEL_ID"]
SLACK_PARENT_MESSAGE_TS = os.environ["SLACK_PARENT_MESSAGE_TS"]

AZURE_AD_TENANT_ID = os.environ["AZURE_AD_TENANT_ID"]
AZURE_AD_CLIENT_ID = os.environ["AZURE_AD_CLIENT_ID"]
AZURE_AD_CLIENT_SECRET = os.environ["AZURE_AD_CLIENT_SECRET"]

# slackのエンドポイント一覧
SLACK_ENDPOINT_USERLIST = "https://slack.com/api/users.list"
SLACK_ENDPOINT_CONVERSATIONSLIST = "https://slack.com/api/conversations.list"
SLACK_ENDPOINT_HISTORY = "https://slack.com/api/conversations.history"
SLACK_ENDPOINT_CHATPOSTMESSAGE = "https://slack.com/api/chat.postMessage"

REQUESTS_HEADER_DICT = {"Authorization": "Bearer " + SLACK_BOT_TOKEN}


# newnew = os.environ["newnew"]


import requests
import pandas as pd
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
# ZoneInfo("Asia/Tokyo")
# ZoneInfo("UTC") # azureはutc基準なので、こっちを使う

import xmltodict
from azure.monitor.query import LogsQueryClient # , QueryTimeRange
# from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential

# Azure 認証情報の設定
# 環境変数 AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID が設定されている前提
# credential = DefaultAzureCredential()
credential = ClientSecretCredential(
    tenant_id=AZURE_AD_TENANT_ID,
    client_id=AZURE_AD_CLIENT_ID,
    client_secret=AZURE_AD_CLIENT_SECRET
)

# ログを取得する期間
end_time = datetime.now(ZoneInfo("UTC"))
start_time = end_time - timedelta(days=1)

# クライアントの初期化
client = LogsQueryClient(credential)

timespan = timedelta(days=1)
japan_zoneinfo = ZoneInfo("Asia/Tokyo") # 読み込み少しでも高速化

output_columns = ["username","ip","TimeGeneratedJapan_str","TimeGeneratedJapan_s_str","TimeGeneratedJapan","resource"]


def request_azure_log(query):
    response = client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=query,
        timespan=timespan
    )

    if response.tables:
        table = response.tables[0]
        return pd.DataFrame(table.rows, columns=table.columns)
    else:
        return None
    
def split_info(x):
    username = ""
    ip = ""
    for _x in x.split(" "):
        if "=" in _x:
            _s = _x.split("=")
            _sk = _s[0]
            _sv = _s[1]
            if _sk == "Username":
                username = _sv
            elif _sk == "IP":
                ip = _sv
    return (username,ip)

def info_user(info_dict):

    username = ""
    ip = ""
    # print(info_dict)
    for _i in info_dict["DataItem"]["EventData"]["Data"]:
        # print(_i)
        if _i["@Name"] == "TargetUserName":
            username = _i["#text"]
        elif _i["@Name"] == "IpAddress":
            ip = _i["#text"]

    return (username,ip)


def log_analysis_monitor():

    # 結果の処理
    query = f"""
AzureDiagnostics
| where Category == "P2SDiagnosticLog" and Message has "Connection successful"
    """

    # 接続元を見る場合
    # query = f"""
    # AzureDiagnostics
    # | where Category == "IKEDiagnosticLog"
    # """

    vpn_df = request_azure_log(query)
    vpn_df["resource"] = "azureVpn接続"

    vpn_df[["username","ip"]] = vpn_df['Message'].map(split_info).to_list()
    vpn_df["TimeGeneratedJapan"] = vpn_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo))
    vpn_df["TimeGeneratedJapan_str"] = vpn_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo).strftime('%Y年%m月%d日 %H時%M分 (%a)'))
    vpn_df["TimeGeneratedJapan_s_str"] = vpn_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo).strftime('%m/%d %H:%M'))
    vpn_df = vpn_df[output_columns]
    vpn_df = vpn_df.drop_duplicates(subset=["username","TimeGeneratedJapan_str"],keep="first")



    query = f"""
Event
| where EventID == 4624
| sort by TimeGenerated desc
    """

    # 4624: アカウントがログオンに成功した。
    # 4625: アカウントのログオンに失敗した（不正アクセス試行の検知に利用）。
    # 4634: アカウントがログオフした（セッション終了）。
    # 4647: ユーザーがログオフを開始した。
    # 4800: ワークステーションがロックされた。
    # 4801: ワークステーションがロック解除された。
    # 4672: 特権が利用された（管理者権限でのログオンなど）。
    # 1149: リモートデスクトップサービスで認証が成功した（RDP接続時）。


    srv_df = request_azure_log(query)
    srv_df["resource"] = "踏み台login"
    srv_df['EventDataDict'] = srv_df['EventData'].map(xmltodict.parse)

    srv_df[['username',"ip"]] = srv_df['EventDataDict'].map(info_user).to_list()
    srv_df["TimeGeneratedJapan"] = srv_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo))
    srv_df["TimeGeneratedJapan_str"] = srv_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo).strftime('%Y年%m月%d日 %H時%M分 (%a)'))
    srv_df["TimeGeneratedJapan_s_str"] = srv_df["TimeGenerated"].map(lambda x :x.astimezone(japan_zoneinfo).strftime('%m/%d %H:%M'))
    srv_df = srv_df[output_columns]
    srv_df = srv_df[srv_df["ip"].str.len() > 2]
    srv_df = srv_df.drop_duplicates(subset=["username","TimeGeneratedJapan_str"],keep="first")



    old_move_top = True
    # new_move_top = False

    df = pd.concat([srv_df,vpn_df]).sort_values("TimeGeneratedJapan",ascending=old_move_top)

    len_df = len(df)

    if len_df != 0:

        msg = "本日以下のアクションがありました。\n\n"

        msg += "時間".ljust(21)
        msg += "行動".ljust(20)
        msg += "割り当てsubnetIP".ljust(16)
        msg += "ユーザー名"
        msg += "\n\n"

        df_key = list(df.columns)
        for _d_tuple in df.values:
            _d = dict(zip(df_key,_d_tuple)) # 辞書型配列に変換

            username = _d["username"]
            ip = _d["ip"]
            time_str = _d["TimeGeneratedJapan_s_str"]
            resource = _d["resource"]

            msg += (
                f"{time_str.ljust(15)}"
                f"{resource.ljust(16)}"
                f"{ip.ljust(20)}"
                
                f"{username}"
                "\n"
                
            )

        msg = msg.strip()

        payload = {
            "channel": SLACK_CHANNEL_ID,
            "text": msg, # 'text': 'app scriptから失礼します。 <@U01GW7NDP7Z>'
            "thread_ts":SLACK_PARENT_MESSAGE_TS
        }

        response = requests.post(SLACK_ENDPOINT_CHATPOSTMESSAGE, headers=REQUESTS_HEADER_DICT, data=payload)
        # display(response.json())

    return None
