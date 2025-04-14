import boto3

comprehend = boto3.client('comprehend')

# You can change this to any log text you want to analyze
log_text = "Unusual API call from IP 198.51.100.23 triggered GuardDuty alert."

response = comprehend.detect_sentiment(
    Text=log_text,
    LanguageCode='en'
)

print("Comprehend AI Threat Classification:")
print(f"Sentiment: {response['Sentiment']}")
print(f"Confidence Scores: {response['SentimentScore']}")
