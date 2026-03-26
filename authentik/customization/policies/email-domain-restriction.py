allowed_domains = ["@<EMAIL_DOMAIN>"]

email = request.context.get("prompt_data", {}).get("email", "")

# Check if email ends with any allowed domain
if any(email.lower().endswith(domain.lower()) for domain in allowed_domains):
    return True

ak_message("Registration is only allowed for approved email domains. Please use your organization email account for registration.")
return False