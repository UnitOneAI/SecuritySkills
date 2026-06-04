import json
from pydantic import BaseModel, ValidationError


class Profile(BaseModel):
    display_name: str
    email_opt_in: bool = False


def load_profile(request_body: bytes) -> Profile:
    parsed = json.loads(request_body)
    return Profile.model_validate(parsed)


try:
    profile = load_profile(request.body)
except (json.JSONDecodeError, ValidationError):
    profile = Profile(display_name="guest")
