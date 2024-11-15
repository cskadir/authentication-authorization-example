function login() {
    // Formdaki verileri al
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    // Giriş isteği için yapılandırma
    const data = {
        username: username,
        password: password
    };

    // Giriş isteğini gönder
    fetch("http://localhost:9696/auth/login", {  // Spring Boot endpoint
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    })
        .then(response => {
            if (response.ok) {
                alert("Giriş başarılı! Hoş geldiniz, " + username);
            } else {
                alert("Giriş başarısız: " + (data.message || "Geçersiz kullanıcı adı veya şifre."));
            }
        })
        .catch(error => {
            console.error("Hata:", error);
            alert("Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.");
        });
}

function logout() {

    fetch("http://localhost:9696/auth/logout", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        }
    })
        .then(response => {
            if (response.ok) {
                alert("Çıkış başarılı!" + username);
            }
        })

}

function openNewTab() {
    // Yeni sekmede açmak için
    window.open("/hello-world", "_blank");
}