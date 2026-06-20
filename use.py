import requests

url = "https://your-live-domain.com/predict"
headers = {
    "X-API-Key": "paste-your-api-key-here"
}
data = {
    "message": "hi"
}

response = requests.post(url, json=data, headers=headers)

if response.status_code == 200:
    result = response.json()
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']:.2f}")
else:
    print("Error:", response.status_code, response.text)
