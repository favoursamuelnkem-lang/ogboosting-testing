// ==========================================
// OG BOOSTING AUTHENTICATION
// ==========================================

const API_URL = "https://ogboosting-testing.onrender.com";

// Get token
const token =
  localStorage.getItem("ogBoostingToken") ||
  sessionStorage.getItem("ogBoostingToken");

// ==========================================
// NO TOKEN = SEND TO LOGIN
// ==========================================
if (!token) {

  console.log("NO TOKEN FOUND");

}

// ==========================================
// VERIFY TOKEN WITH SERVER
// ==========================================

if (token) {

  fetch(`${API_URL}/api/auth/me`, {

    method: "GET",

    headers: {
      "Authorization": `Bearer ${token}`
    }

  })

  .then(async response => {

    const data = await response.json();

    if (!response.ok || !data.success) {

      // Token is invalid/expired
      localStorage.removeItem("ogBoostingToken");
      localStorage.removeItem("ogBoostingUser");

      sessionStorage.removeItem("ogBoostingToken");
      sessionStorage.removeItem("ogBoostingUser");

     console.log("TOKEN VERIFICATION FAILED", data);

      return;
    }

    // Save latest user information
    localStorage.setItem(
      "ogBoostingUser",
      JSON.stringify(data.user)
    );

    console.log("Authenticated:", data.user);

  })

  .catch(error => {

    console.error("Authentication check failed:", error);

  });

}