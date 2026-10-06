
const API_URL = "https://ogboosting-testing.onrender.com";
const token =
  localStorage.getItem("ogBoostingToken") ||
  sessionStorage.getItem("ogBoostingToken");
if (!token) {

  console.log("NO TOKEN FOUND");

}

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
      localStorage.removeItem("ogBoostingToken");
      localStorage.removeItem("ogBoostingUser");

      sessionStorage.removeItem("ogBoostingToken");
      sessionStorage.removeItem("ogBoostingUser");

     console.log("TOKEN VERIFICATION FAILED", data);

      return;
    }
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