// Server-supplied text is untrusted as far as this page is concerned - it includes level
// commentary and, for some levels, a decoy value - and was previously written into the page via
// innerHTML, which parses its argument as markup rather than plain text. Rendering it through a
// bold text node instead means the string can only ever display as text, never execute as markup.
function renderServerText(container, label, text) {
  container.textContent = "";
  if (label) {
    let labelNode = document.createElement("strong");
    labelNode.textContent = label;
    container.appendChild(labelNode);
    container.appendChild(document.createTextNode(" "));
  }
  let textNode = document.createElement("strong");
  textNode.textContent = text;
  container.appendChild(textNode);
}

function loadChallenge() {
  let url = getUrlForVulnerabilityLevel();
  doGetAjaxCall(displayChallenge, url, true);
}

function displayChallenge(data) {
  let challengeDiv = document.getElementById("challenge");
  renderServerText(challengeDiv, null, data.content);
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
        renderServerText(resultDiv, null, "Please enter a password guess.");
        resultDiv.style.color = "red";
        return;
      }

      let params = new URLSearchParams();
      params.append("password", password);

      doGetAjaxCall(
        appendResponseCallback,
        url + "?" + params.toString(),
        true
      );
    });
}

function appendResponseCallback(data) {
  let resultDiv = document.getElementById("result");
  renderServerText(resultDiv, "Result:", data.content);
  resultDiv.className = data.isValid ? "result-success" : "result-failure";
}

addingEventListenerToSubmitButton();
loadChallenge();
