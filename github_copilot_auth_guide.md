### **How to Use the New Authentication Flow**

The new authentication flow is designed to be more flexible and scalable, allowing you to manage multiple users and their authentication tokens programmatically. Here's a step-by-step guide on how to use it:

#### **Step 1: Initiate the Login Flow**

First, you'll need to create an instance of the `GithubCopilotAuthManager` and call the `start_login()` method. This will return a dictionary containing the `verification_uri` and `user_code`, which you can then display to your users.

```python
from litellm.llms.github_copilot import GithubCopilotAuthManager

# 1. Start the login process
auth_manager = GithubCopilotAuthManager()
login_info = auth_manager.start_login()

# 2. Display the login info to the user
print(f"Please visit {login_info['verification_uri']} and enter the code: {login_info['user_code']}")
```

#### **Step 2: Poll for the Authentication Token**

After the user has authenticated in their browser, you can call the `poll_for_token()` method with the `device_code` from the previous step. This will poll GitHub for the access token and, once obtained, will also fetch the API key.

```python
# 3. Poll for the authentication token
# This will block until the user has successfully authenticated
auth_info = auth_manager.poll_for_token(login_info['device_code'])

print("Authentication successful!")
print(auth_info)
```

The `auth_info` dictionary will look something like this:

```json
{
  "access_token": "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "api_key_info": {
    "token": "tid_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "expires_at": 1672531199
  }
}
```

#### **Step 3: Use the `auth_info` in the Completion Function**

Finally, you can pass the `auth_info` dictionary directly to the `completion` function. This will bypass the need for file-based authentication and allow you to manage multiple users' tokens in memory.

```python
from litellm import completion

# 4. Use the auth_info to make a completion request
response = completion(
    model="github_copilot/gpt-4o",
    messages=[{"role": "user", "content": "hello from litellm"}],
    auth_info=auth_info
)

print(response)
```

This new flow gives you much more control over the authentication process and makes it easier to integrate the GitHub Copilot API into your applications.
