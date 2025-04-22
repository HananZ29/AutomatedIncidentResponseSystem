import boto3

comprehend = boto3.client('comprehend')

def analyze_sentiment(text):
    response = comprehend.detect_sentiment(Text=text, LanguageCode='en')
    return response['Sentiment'].upper()  # e.g., POSITIVE, NEGATIVE, NEUTRAL, MIXED

if __name__ == "__main__":
    log_text = "Unusual API call from IP 198.51.100.23 triggered GuardDuty alert."

    sentiment = analyze_sentiment(log_text)
    response = comprehend.detect_sentiment(Text=log_text, LanguageCode='en')

    print("Comprehend AI Threat Classification:")
    print(f"Sentiment: {sentiment}")
    print(f"Confidence Scores: {response['SentimentScore']}")
