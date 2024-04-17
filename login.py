import streamlit as st
import boto3


USER_POOL_ID = st.secrets["USER_POOL_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
REGION = st.secrets["REGION"]
IDENTITYPOOLID = st.secrets["IDENTITY_POOL_ID"]
ACCOUNTID = st.secrets["ACCOUNT_ID"]



# Function use to authenticate user credentials from Amazon Cognito
def authenticate(username, password):
    try:
        client = boto3.client('cognito-idp', region_name=REGION)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            }
        )
        st.session_state['auth_response'] = response
        return response
    except Exception as e:
        st.error(f"Authentication error: {e}")
        return None



# Function use to get AWS credentials to access other services like Q Application etc 
def GetuserCredentials(idtoken, access_token):
    try:
        clientidp = boto3.client('cognito-idp', region_name=REGION)
        client = boto3.client('cognito-identity', region_name=REGION)
        user = clientidp.get_user(
                 AccessToken=access_token
        )   
        username = user["Username"]
        logins = {
            f'cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}': idtoken
        }
        response = client.get_id(
            AccountId=ACCOUNTID,
            IdentityPoolId=IDENTITYPOOLID,	
            Logins=logins
        )
        identityId = response['IdentityId']
        responsee = client.get_credentials_for_identity(
                IdentityId=identityId,
                Logins=logins
        )
        accesskeyID = responsee['Credentials']['AccessKeyId']
        secretkey = responsee['Credentials']['SecretKey']
        sessiontoken = responsee['Credentials']['SessionToken']

        sts_client = boto3.client('sts',
        aws_access_key_id=accesskeyID,
        aws_secret_access_key=secretkey,
        aws_session_token=sessiontoken)

        responseforUserid = sts_client.get_caller_identity()
        userid = responseforUserid["UserId"]
        arn  = responseforUserid["Arn"]
        userdata = {
            "accesskeyID": accesskeyID,
            "secretkey": secretkey,
            "sessiontoken": sessiontoken,
            "userid": userid,
            "arn": arn,
            "username": username
        }
        st.session_state['user'] = userdata
        st.rerun()

    except Exception as e:
        st.error("Failed to get credentials: " + str(e))


# Function use update password
def respond_to_auth_challenge(username, new_password, session):
    try:
        client = boto3.client('cognito-idp', region_name=REGION)
        response = client.respond_to_auth_challenge(
            ChallengeName='NEW_PASSWORD_REQUIRED',
            ClientId=CLIENT_ID,
            ChallengeResponses={
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            },
            Session=session
        )
        return response
    except Exception as e:
        st.error(f"Error updating password: {e}")
        return None



# function use to handle update password challenge Automatically
def update_password(username,password, session):
    new_password = password
    update_response = respond_to_auth_challenge(username, new_password, session)
    if update_response:
        auth_response = authenticate(username, new_password)
        st.success("Authentication successful!")
        st.success("Waiting for Other Services Access verification")
        st.session_state['auth_response'] = auth_response
        st.session_state['isuserloggedin'] = True
        id_token = auth_response['AuthenticationResult']['IdToken']
        access_token = auth_response['AuthenticationResult']['AccessToken']
        GetuserCredentials(id_token, access_token)
    else:
        st.error("Error updating password. Please try again.")



