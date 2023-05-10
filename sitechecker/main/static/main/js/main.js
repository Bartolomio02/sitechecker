const InputUrlSubmit = document.querySelector('#InputUrlSubmit');
const InputUrl = document.querySelector('#InputUrl');


let intervalId = setInterval(function() {
    let elements = document.querySelectorAll('.host-item__name-scan');
    if (elements.length > 0) {
      clearInterval(intervalId);
      // Привязать обработчик событий click к каждому элементу в списке
      elements.forEach(function(element) {
        element.addEventListener('click', function(event) {
          InputUrl.value = event.target.innerText;
            InputUrlSubmit.click();
        });
      });
    }
  }, 1000); // Поиск будет осуществляться каждую секунду (1000 миллисекунд)\


let intervalId2 = setInterval(function() {
    let elements = document.querySelectorAll('.host-item__name-del');
    if (elements.length > 0) {
      clearInterval(intervalId2);
      // Привязать обработчик событий click к каждому элементу в списке
      elements.forEach(function(element) {
        element.addEventListener('click', function(event) {
          console.log('Вы нажали на элемент:', event.target);
        });
      });
    }
  }, 1000); // Поиск будет осуществляться каждую секунду (1000 миллисекунд)


  // добавляем обработчик клика на родительский элемент
document.getElementById('accordionFlushExample').addEventListener('click', function(event) {
  // проверяем, является ли элемент, на который был совершен клик, элементом удаления
  if (event.target.matches('.accordion-delete')) {
    // находим родительский элемент для удаления
    var item = event.target.closest('.accordion-item');
    // удаляем элемент
    item.parentNode.removeChild(item);
  }
});

// добавляем обработчик клика на родительский элемент
document.getElementById('ajax-result-main').addEventListener('click', function(event) {
  // проверяем, является ли элемент, на который был совершен клик, элементом удаления
  if (event.target.matches('.host-item__name-del')) {
    // находим родительский элемент для удаления
    var item = event.target.closest('.host-item');
    // удаляем элемент
    item.parentNode.removeChild(item);
  }
});

// добавляем обработчик клика на родительский элемент
document.getElementById('ajax-result-main').addEventListener('click', function(event) {
  // проверяем, является ли элемент, на который был совершен клик, элементом удаления
  if (event.target.matches('.host-item__name-scan')) {
    // вставляем значение в поле ввода
    InputUrl.value = event.target.closest('.host-item').querySelector('.host-item__name-text').innerText;
    InputUrlSubmit.click();
  }
});



InputUrlSubmit.addEventListener('click', function(event) {
  let accordionItemsCount = document.querySelectorAll('.accordion-item').length;
  let accordionhtml = document.querySelector('#accordionFlushExample').innerHTML;
  var auto_scan_checkbox = document.getElementById('auto-scan');
  var auto_adding_domain = document.getElementById('auto-adding');
  var isChecked = auto_scan_checkbox.checked;
  var scan_port = document.getElementById('scan-ports').value;
  console.log(scan_port);
  var thread_count = document.getElementById('thread-count').value;
  if (isChecked != true && auto_adding_domain.checked != true) {

    if (accordionItemsCount > 0) {
      data = {
        'site': InputUrl.value,
        'accordionItemsCount': accordionItemsCount,
        'accordionhtml': accordionhtml,
        'auto-scan': isChecked,
        'auto-adding-domains': auto_adding_domain.checked,
        'thread-count': thread_count,
        'scan-ports': scan_port
      };
      console.log(data);
      $.ajax({
        type: "POST",
        url: "/api/scanhost/details",
        data: data,
        success: function(response) {
          accordionhtml += response.host;
          document.querySelector('#accordionFlushExample').innerHTML = accordionhtml;
        }
      });
    } else {
      data = {
        'site': InputUrl.value,
        'accordionItemsCount': 0,
        'accordionhtml': '',
        'auto-scan': isChecked,
        'auto-adding-domains': auto_adding_domain.checked,
        'thread-count': thread_count,
        'scan-ports': scan_port
      };
      console.log(data);
      $.ajax({
        type: "POST",
        url: "/api/scanhost/details",
        data: data,
        success: function(response) {
          accordionhtml += response.host;
          document.querySelector('#accordionFlushExample').innerHTML = accordionhtml;
        }
      });
    }}
  else {
    const data = {
      'site': InputUrl.value,
      'accordionItemsCount': accordionItemsCount,
      'accordionhtml': accordionhtml,
      'auto-scan': isChecked,
      'auto-adding-domains': auto_adding_domain.checked,
      'thread-count': thread_count,
      'scan-ports': scan_port
    };
    fetch("/api/scanhost/details", {
      method: "POST",
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    }).then(function(response) {
      const reader = response.body.getReader();
      return new ReadableStream({
        start(controller) {
          function push() {
            reader.read().then(({ done, value }) => {
              if (done) {
                controller.close();
                return;
              }
              controller.enqueue(value);
              push();
            })
          }
          push();
        }
      })
    }).then(function(stream) {
      const reader = stream.getReader();
      return new ReadableStream({
        start(controller) {
          function push() {
            reader.read().then(({ done, value }) => {
              if (done) {
                controller.close();
                return;
              }


              const textDecoder = new TextDecoder("utf-8");
              const decodedData = textDecoder.decode(value);
              console.log(decodedData);
              console.log(typeof decodedData);
              // проверяем строку на наличие разделителя
              if (decodedData.indexOf("}{") !== -1) {
                // разделяем строку на две
                const jsonDataArr = decodedData.split("}{");
                // обрабатываем каждую строку
                jsonDataArr.forEach(function(jsonData, index) {
                  // добавляем скобки для преобразования в JSON-объект
                  jsonData = (index === 0 ? jsonData + "}" : "{" + jsonData);
                  // преобразуем строку в объект JSON
                  const data = JSON.parse(jsonData);
                  // обрабатываем полученный объект
                  processJSONData(data);
                });
              } else {
                // строка имеет правильный формат, преобразуем ее в объект JSON
                const data = JSON.parse(decodedData);
              // console.log(data.host);

              if (data.host == undefined) {
                data.host = '';
                const scan_domain = document.querySelector('#auto-scan-domain');
                console.log(data.domain);
                scan_domain.value = scan_domain.value + (scan_domain.value ? "," : "") + data.domain;
              }
              accordionhtml += data.host;
              // accordionhtml += text;
              document.querySelector('#accordionFlushExample').innerHTML = accordionhtml;
              push();
            }
          })
        }
        push();
      }
    })
  })
}
});



// получаем элементы кнопок и input
const plusBtn = document.querySelector('.plus-btn');
const minusBtn = document.querySelector('.minus-btn');
const input = document.querySelector('input[name="quantity"]');

// обработчик события для кнопки "+"
plusBtn.addEventListener('click', () => {
  if (input.value < 10) {
  input.value = parseInt(input.value) + 1;
  }
});

// обработчик события для кнопки "-"
minusBtn.addEventListener('click', () => {
  if (input.value > 1) {
    input.value = parseInt(input.value) - 1;
  }
});

// валидация для input, чтобы принимать только числовые значения и проверка по колву потоков
input.addEventListener('input', () => {
  let value = input.value.replace(/\D/g, '');
  if (value < 1) {
    value = 1;
  } else if (value > 10) {
    value = 10;
  }
  input.value = value;
  });
