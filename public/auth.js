let API_BASE_URL = 'http://localhost:3000';



// Регистрация
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value.trim();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (password !== confirmPassword) {
        showError('Пароли не совпадают');
        return;
    }

    // Проверка почты на валидность
    if (!isValidEmail(email)) {
        showError('Неверный формат почты');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/register`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, username, password })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Неизвестная ошибка');

        showSuccess('Регистрация успешна!');
        setTimeout(() => window.location.href = '/login.html', 1500);
    } catch (error) {
        showError(`Ошибка: ${error.message}`);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    // Мы сразу устанавливаем URL, так как он фиксированный
    console.log("Страница загружена, API_BASE_URL =", API_BASE_URL);
});

function isValidEmail(email) {
    // Улучшенная регулярка для проверки email
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

// Обработчик входа
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    // Предотвращаем стандартное поведение формы
    e.preventDefault();
    console.log("Login form submitted, API_BASE_URL =", API_BASE_URL);

    const identifier = document.getElementById('loginIdentifier').value.trim();
    const password = document.getElementById('loginPassword').value;

    // Валидация полей
    if (!identifier || !password) {
        alert("Пожалуйста, заполните все поля");
        return;
    }
    if (identifier.includes('@')) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(identifier)) {
            alert("Введите корректный email");
            return;
        }
    }

    try {
        // Отправляем AJAX-запрос на вход
        const response = await fetch(`${API_BASE_URL}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ identifier, password })
        });
        console.log("Ответ сервера получен. Статус:", response.status);

        const data = await response.json();
        console.log("Полученные данные:", data);

        if (!response.ok) throw new Error(data.error || 'Неизвестная ошибка');

        showSuccess('Вход выполнен!');
        localStorage.setItem('currentUser', JSON.stringify(data.user));

        // Редирект через 1 секунду на test.html
        setTimeout(() => {
            console.log("Редирект на /test.html");
            window.location.href = '/test.html';
        }, 1000);
    } catch (error) {
        console.error("Ошибка при логине:", error);
        showError(`Ошибка: ${error.message}`);
    }
});

// Вспомогательные функции
function showError(message) {
    const container = document.querySelector('.auth-container');
    container.prepend(createMessageDiv('error-message', message));
}

function showSuccess(message) {
    const container = document.querySelector('.auth-container');
    container.prepend(createMessageDiv('success-message', message));
}

function createMessageDiv(className, text) {
    const div = document.createElement('div');
    div.className = className;
    div.textContent = text;
    setTimeout(() => div.remove(), 3000);
    return div;
}

function sendClientLog(message, level = "INFO") {
    fetch(`${API_BASE_URL}/api/log`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ message, level })
    }).catch(err => {
        // Выводим ошибку отправки лога, если что-то пойдёт не так
        originalConsoleLog("Ошибка отправки лога:", err);
    });
}

// Сохраняем оригинальную функцию console.log
const originalConsoleLog = console.log;

// Переопределяем console.log таким образом, чтобы он отправлял логи на сервер
console.log = function(...args) {
    // Вызываем оригинальный console.log для вывода в консоль браузера
    originalConsoleLog.apply(console, args);
    // Отправляем лог на сервер, объединяя все аргументы в одну строку
    sendClientLog(args.join(" "), "INFO");
};

function init() {
    console.log("Документ загружен. Инициализация выполнена.");
    // Здесь можно добавить дополнительные действия инициализации
}

// Инициализация при загрузке
document.addEventListener('DOMContentLoaded', init);