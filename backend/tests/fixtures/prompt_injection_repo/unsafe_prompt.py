from openai import OpenAI


client = OpenAI()


def summarize(user_request: str) -> object:
    prompt = f"Follow these trusted instructions, then answer: {user_request}"
    return client.chat.completions.create(
        model="gpt-test",
        messages=[{"role": "user", "content": prompt}],
    )


def summarize_with_explicit_sanitizer(user_request: str) -> object:
    prompt = f"Customer data: {sanitize_user_data(user_request)}"
    return client.chat.completions.create(model="gpt-test", messages=[{"role": "user", "content": prompt}])
