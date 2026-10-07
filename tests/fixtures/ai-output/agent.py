import os


def execute_model_response(client):
    response = client.responses.create(model="example", input="test")
    llm_output = response.output_text
    os.system(llm_output)
