import requests

email = request.context.get("prompt_data", {}).get("email", "")
name = request.context.get("prompt_data", {}).get("name", "")

if not email or not email.endswith("@<EMAIL_DOMAIN>"):
    ak_message("Only @<EMAIL_DOMAIN> email addresses are allowed.")
    return False

if not name:
    ak_message("Name is required.")
    return False

try:
    response = requests.post(
        "http://<AUTHENTIK_IP>:5000/create-user",
        json={
            "email": email,
            "name": name
        },
        headers={
            "Authorization": "Bearer <API_KEY>",
            "Content-Type": "application/json"
        },
        timeout=10
    )
    
    result = response.json()
    
    if response.status_code == 200 and result.get("success"):
        ak_message(f"Account created! Your username is: {result.get('username')}. Please go through the login and click Forgot Password to authenticate via your organization email.")
        return True
    elif response.status_code == 409:
        ak_message("An account with this email already exists.")
        return False
    else:
        ak_logger.error(f"Enrollment API error: {result.get('error', 'Unknown error')}")
        ak_message("Account creation failed. Please try again later.")
        return False
        
except Exception as e:
    ak_logger.error(f"Exception during account creation: {str(e)}")
    ak_message("An error occurred during account creation. Please try again later.")
    return False