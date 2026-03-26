return {
    "email": notification.event.context.get("prompt_data", {}).get("email", ""),
    "name": notification.event.context.get("prompt_data", {}).get("name", ""),
    "password": notification.event.context.get("prompt_data", {}).get("password", ""),
}