const root = document.getElementById("view");
window.addEventListener("message", (event) => {
  // ui:// resources post their markup here
  root.innerHTML = event.data.html;
});
