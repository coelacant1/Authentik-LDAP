import requests

# This policy enables disabled accounts during password recovery
# Bind this AFTER email verification in your recovery flow

# Get email from flow context
email = None

# Try to get email from pending_user
if hasattr(request, 'context') and 'pending_user' in request.context:
    pending_user = request.context['pending_user']
    if hasattr(pending_user, 'email'):
        email = pending_user.email

# Also try plan.context
if not email and hasattr(request, 'plan') and hasattr(request.plan, 'context'):
    if 'pending_user' in request.plan.context:
        pending_user = request.plan.context['pending_user']
        if hasattr(pending_user, 'email'):
            email = pending_user.email

# Try to get from authenticated user as fallback
if not email and hasattr(request, 'user') and hasattr(request.user, 'email'):
    email = request.user.email

# If no email found, block flow (fail closed)
if not email:
    ak_logger.error("No email found in context - blocking flow")
    ak_message("Unable to verify your identity. Please try again.")
    return False

ak_logger.info(f"Processing account enablement for {email}")

# Attempt to enable the account
try:
    ak_logger.info(f"Calling enable API for {email}")
    
    enable_response = requests.post(
        "http://<AUTHENTIK_IP>:5000/enable-user",
        json={"email": email},
        headers={
            "Authorization": "Bearer <API_KEY>",
            "Content-Type": "application/json"
        },
        timeout=10
    )
    
    enable_result = enable_response.json()
    
    if enable_response.status_code == 200 and enable_result.get("success"):
        actions = enable_result.get('actions', [])
        ak_logger.info(f"Successfully enabled account for {email}: {actions}")
        ak_message("Your account has been verified and enabled!")
        return True
    else:
        error_msg = enable_result.get('error', 'Unknown error')
        ak_logger.error(f"Failed to enable account for {email}: {error_msg}")
        ak_message("Unable to enable your account. Please contact support.")
        return False
        
except Exception as e:
    ak_logger.error(f"Exception in account verification policy: {str(e)}")
    ak_message("Unable to verify account status. Please try again later.")
    return False