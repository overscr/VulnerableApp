function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  // The level endpoints only answer POST now, so the description is fetched with an empty
  // submission instead of a GET.
  doPostAjaxCall(displayChallenge, url, true, "", {
    "Content-Type": "application/x-www-form-urlencoded",
  });
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  challengeDiv.innerHTML = "<strong>" + data.content + "</strong>";
  if (data.isValid) {
    challengeDiv.className = "challenge-secure";
  } else {
    challengeDiv.className = "challenge-vulnerable";
  }
}

function addingEventListenerToSubmitButton() {
  document
    .getElementById("submitButton")
    .addEventListener("click", function () {
      let url = getUrlForVulnerabilityLevel();
      let password = document.getElementById("password").value;

      if (!password) {
        let resultDiv = document.getElementById("result");
        resultDiv.innerHTML = "<strong>Please enter a password guess.</strong>";
        resultDiv.style.color = "red";
        return;
      }

      // The guess goes in the request body, not the URL — a URL is written verbatim into
      // access logs and browser history and is replayed in any outbound Referer header.
      let body = new URLSearchParams();
      body.append("password", password);

      doPostAjaxCall(appendResponseCallback, url, true, body.toString(), {
        "Content-Type": "application/x-www-form-urlencoded",
      });
    });
}

function appendResponseCallback(data) {
  let resultDiv = document.getElementById("result");
  if (data.isValid) {
    resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
    resultDiv.className = "result-success";
  } else {
    resultDiv.innerHTML = "<strong>Result:</strong> " + data.content;
    resultDiv.className = "result-failure";
  }
}

addingEventListenerToSubmitButton();
loadChallenge();
