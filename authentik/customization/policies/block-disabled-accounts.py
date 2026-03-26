import requests

# This policy blocks login for disabled LDAP accounts
# Internal authentik users are allowed to pass through
# Bind this to your authentication flow (e.g., default-authentication-flow)
# as an Expression Policy on the authentication stage

# Get the user attempting to login
user = request.user

# If no user context, allow the flow to continue (we're not at the right stage yet)
if not user or not hasattr(user, 'email'):
    ak_logger.info("No user context found - allowing flow to continue")
    return True

email = user.email

# Check if user is from LDAP source
is_ldap_user = False

try:
    # Method 1: Check user sources
    user_sources = user.sources.all()
    for source in user_sources:
        # Check if any source is an LDAP source
        # Adjust based on your LDAP source name or type
        if hasattr(source, 'component') and 'ldap' in source.component.lower():
            is_ldap_user = True
            ak_logger.info(f"User {email} identified as LDAP user via source: {source.name}")
            break
    
    # Method 2: Alternative - check by specific source name if you know it
    # Uncomment and adjust if you prefer this method:
    # ldap_source_names = ["ldap-source", "active-directory"]  # Add your LDAP source names
    # for source in user_sources:
    #     if source.name in ldap_source_names:
    #         is_ldap_user = True
    #         ak_logger.info(f"User {email} identified as LDAP user via source name: {source.name}")
    #         break
    
except Exception as e:
    ak_logger.error(f"Error checking user sources for {email}: {str(e)}")
    # If we can't determine the source, assume LDAP for safety
    is_ldap_user = True

# If user is not from LDAP (i.e., internal authentik user), allow login
if not is_ldap_user:
    ak_logger.info(f"User {email} is an internal authentik user - allowing login without status check")
    return True

# User is from LDAP - proceed with status check
ak_logger.info(f"Checking account status for LDAP user login attempt: {email}")

try:
    # Check if the account is enabled in AD
    check_response = requests.post(
        "http://<AUTHENTIK_IP>:5000/check-user-status",
        json={"email": email},
        headers={
            "Authorization": "Bearer <API_KEY>",
            "Content-Type": "application/json"
        },
        timeout=10
    )
    
    check_result = check_response.json()
    
    if check_response.status_code != 200 or not check_result.get("success"):
        error = check_result.get('error', 'Unknown error')
        ak_logger.error(f"Failed to check account status for {email}: {error}")
        # Fail closed - block login if we can't verify account status
        ak_message("Unable to verify account status. Please try again later.")
        return False
    
    is_active = check_result.get("is_active", False)
    is_locked = check_result.get("is_locked", False)
    
    ak_logger.info(f"Account {email}: is_active={is_active}, is_locked={is_locked}")
    
    # Block login if account is disabled or locked
    if not is_active:
        ak_logger.warning(f"Login denied for {email}: account is disabled")
        ak_message("Your account is disabled, please use Forgot Password to re-enable account.")
        return False
    
    if is_locked:
        ak_logger.warning(f"Login denied for {email}: account is locked")
        ak_message("Your account is locked, please use Forgot Password to re-enable account.")
        return False
    
    # Account is enabled and unlocked - allow login
    ak_logger.info(f"Login allowed for {email}: account is active")
    return True
    
except Exception as e:
    # Fail closed - block login if we can't verify account status
    ak_logger.error(f"Exception in login check policy for {email}: {str(e)}")
    ak_message("Unable to verify account status. Please try again later.")
    return False