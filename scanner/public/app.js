function copyText(id, btn) {
  var text = document.getElementById(id).innerText;
  var old = btn.innerText;

  navigator.clipboard.writeText(text).then(function () {
    btn.innerText = "Скопійовано";
  }).catch(function () {
    btn.innerText = "Виділіть текст вручну";
  });

  setTimeout(function () {
    btn.innerText = old;
  }, 1500);
}
