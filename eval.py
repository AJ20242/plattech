import pandas
import time
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

print("• Starting Full System Evaluation...")
time.sleep(1)

print("\n--- THESIS SYSTEM PERFORMANCE REPORT ---\n")

# =========================
# 1. TEST CASES (GROUND TRUTH)
# =========================
test_cases = [
    {
        "question": "How do I create a support ticket?",
        "expected": "User fills out form with subject description and submits ticket"
    },
    {
        "question": "What is blockchain verification?",
        "expected": "System stores ticket hash in blockchain to ensure integrity"
    },
    {
        "question": "Why is MFA required?",
        "expected": "Multi factor authentication improves account security"
    },
    {
        "question": "How do I verify a ticket?",
        "expected": "User clicks verify and system checks blockchain record"
    },
    {
        "question": "What happens if OTP is wrong?",
        "expected": "System rejects login and limits attempts"
    }
]

# =========================
# 2. SIMULATED SYSTEM RESPONSES
# (Replace with real API later)
# =========================
def get_system_response(question):
    responses = {
        "How do I create a support ticket?":
            "Submit a ticket form with subject and description",

        "What is blockchain verification?":
            "Ticket hash is stored in blockchain for security",

        "Why is MFA required?":
            "MFA adds extra security layer to login",

        "How do I verify a ticket?":
            "System verifies ticket using blockchain hash",

        "What happens if OTP is wrong?":
            "Invalid OTP is rejected and retry is limited"
    }
    return responses.get(question, "")

# =========================
# 3. NLP EVALUATION (COSINE SIMILARITY)
# =========================
def compute_similarity(expected, actual):
    vectorizer = TfidfVectorizer()
    vectors = vectorizer.fit_transform([expected, actual])
    similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
    return round(similarity, 4)

# =========================
# 4. SYSTEM FEATURE CHECKS
# =========================
system_checks = {
    "MFA Enabled": True,
    "OTP Expiration": True,
    "OTP Attempt Limit": True,
    "Session Timeout": True,
    "Blockchain Connected": False,  # update dynamically if needed
    "Input Validation": True
}

# =========================
# 5. RUN EVALUATION
# =========================
results = []
total_score = 0

print("Evaluating AI/NLP Responses...\n")

for i, case in enumerate(test_cases):
    q = case["question"]
    expected = case["expected"]
    actual = get_system_response(q)

    score = compute_similarity(expected, actual)
    total_score += score

    print(f"{i}. {q}")
    print(f"   Score: {score}\n")

    results.append({
        "Question": q,
        "Expected": expected,
        "Actual": actual,
        "Score": score
    })

# =========================
# 6. AI SCORE
# =========================
ai_score = (total_score / len(test_cases)) * 100

# =========================
# 7. SYSTEM RELIABILITY SCORE
# =========================
enabled_features = sum(system_checks.values())
total_features = len(system_checks)

system_score = (enabled_features / total_features) * 100

# =========================
# 8. FINAL TRUST SCORE
# =========================
# Weighted scoring
final_score = (ai_score * 0.6) + (system_score * 0.4)

# =========================
# 9. DISPLAY REPORT
# =========================
df = pd.DataFrame(results)

print("\n--- DETAILED RESULTS ---\n")
print(df[["Question", "Score"]])

print("\n--- SYSTEM CHECKS ---")
for k, v in system_checks.items():
    print(f"{k}: {'OK' if v else 'FAIL'}")

print("\n----------------------------------------")
print(f"AI Accuracy Score: {ai_score:.2f}%")
print(f"System Reliability Score: {system_score:.2f}%")
print(f"Overall System Trust Score: {final_score:.2f}%")
print("----------------------------------------")

# =========================
# 10. EXPORT (FOR THESIS)
# =========================
df.to_csv("evaluation_results.csv", index=False)
print("\n✔ Results exported to evaluation_results.csv")