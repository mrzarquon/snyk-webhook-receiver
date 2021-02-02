import hashlib
import hmac
import os
import json

from typing import Optional

from fastapi import FastAPI, Header, Request
from fastapi.encoders import jsonable_encoder

from pydantic import BaseModel

# grab the webtoken from env
token = os.getenv("SNYK_WEB_TOKEN")

class WebHookEvent(BaseModel):
    project: dict
    org: dict
    newIssues: list

def verify(payload, secret, signature):
    signature=signature.split('=')[1]

    payload = json.dumps(payload)
    
    payload = payload.encode()
    secret = secret.encode()
    
    digest = hmac.new(key=secret, msg=payload, digestmod=hashlib.sha256).hexdigest()

    return signature == digest


def cleanup(project: dict, org: dict, issues: list) -> dict:
    event: dict = {}

    event['project'] = project
    event['product_id'] = project['id']
    event['product_name'] = project['name']
    event['project_url'] = project['browseUrl']
    event['org_id'] = org['id']
    event['org_name'] = org['name']
    event['org_slug'] = org['slug']
    event['org_url'] = org['url']
    event['org_group'] = org['group']
    event['org_created'] = org['created']
    event['issues_count'] = len(issues)

    if len(issues) > 0:
        event['issues'] = slim(issues)
        event['worst'] = sorted(event['issues'], key=lambda d: d['priorityScore'], reverse=True)[0]
    else:
        event['issues'] = []

    return event

def extract(d: dict, keep: list) -> dict:
    keep = [
        'title',
        'severity',
        'url',
        'identifies',
        'credit',
        'exploitMaturity',
        'semver',
        'publicationTime',
        'disclosureTime',
        'CVSSv3',
        'cvssScore',
        'functions',
        'patches',
        'nearestFixedInVersion'
        ]
    return dict(((k, d[k]) for k in keep if k in d))

def remove(d: dict, remove: list) -> dict:
    [d.pop(k) for k in remove if k in d]
    return d

def slim(issues) -> list:
    flat_issues: list = []

    rm = ['description','id']

    # I really don't want to descend N levels to get issues
    # dict1.update(dict2)
    for i in range(0, len(issues)):
        issue = issues[i]
        issue.update(remove(issue['issueData'], rm))
        issue.pop('issueData')
        flat_issues.append(issue)

    return flat_issues

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.post("/webhook/")
async def create_item(
    event: WebHookEvent,
    user_agent: str = Header(None),
    x_hub_signature: str = Header(None),
    x_snyk_timestamp: str = Header(None)
    ):

    is_valid = verify(jsonable_encoder(event), token, x_hub_signature)

    slim_event = cleanup(event.project, event.org, event.newIssues)

    bar = {
        "agent" : user_agent,
        "timestamp": x_snyk_timestamp,
        "signature": x_hub_signature,
        "verify": is_valid,
        "event": slim_event
    }
    return bar