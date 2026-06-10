from dataclasses import dataclass
import yaml


@dataclass(frozen=True)
class EmailJob:
    recipient: str
    template: str


JOB_TYPES = {
    "email": EmailJob,
}


def parse_job(raw_yaml):
    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
        raise ValueError("job must be an object")

    job_type = data.get("type")
    if job_type not in JOB_TYPES:
        raise ValueError("unknown job type")

    payload = data.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    return JOB_TYPES[job_type](
        recipient=validate_string(payload.get("recipient"), 320),
        template=validate_string(payload.get("template"), 80),
    )


def validate_string(value, max_length):
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError("invalid field")
    return value
