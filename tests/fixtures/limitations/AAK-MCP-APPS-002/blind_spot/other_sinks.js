const root = document.getElementById("view");
window.addEventListener("message", (event) => {
  // ui:// resources post their markup here
  $("#view").html(event.data.html);
  document.write(event.data.html);
  root.srcdoc = event.data.html;
});
