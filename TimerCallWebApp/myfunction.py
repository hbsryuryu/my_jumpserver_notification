import os
from dotenv import load_dotenv
load_dotenv(override=True)

WORKSPACE_ID = os.environ["WORKSPACE_ID"]
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_CHANNEL_ID = os.environ["SLACK_CHANNEL_ID"]
SLACK_PARENT_MESSAGE_TS = os.environ["SLACK_PARENT_MESSAGE_TS"]

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
from azure.identity import DefaultAzureCredential

# Azure 認証情報の設定
# 環境変数 AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID が設定されている前提
credential = DefaultAzureCredential()

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
    

def log_analysis_monitor():
    return None