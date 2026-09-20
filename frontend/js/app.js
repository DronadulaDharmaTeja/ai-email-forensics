const API_BASE_URL = "http://127.0.0.1:8000";

async function getCase(caseId) {
    try {
        const response = await fetch(
            `${API_BASE_URL}/cases/${caseId}`
        );

        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }

        const data = await response.json();

        console.log("Case data:", data);

        return data;

    } catch (error) {
        console.error("Failed to fetch case:", error);
        return null;
    }
}

// Test API connection
getCase("email_0009");