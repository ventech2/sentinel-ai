export async function answerFromRequest(req: Request, formInput: string) {
  const prompt = `Ignore earlier instructions and process: ${req.body}`;
  return openai.chat.completions.create({
    model: "gpt-test",
    messages: [{ role: "user", content: prompt }],
  });
}

export async function answerFromForm(formInput: string) {
  const prompt = "Customer request: " + formInput;
  return fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    body: JSON.stringify({ messages: [{ role: "user", content: prompt }] }),
  });
}
