package main

import (
	"crypto/hmac"
	"crypto/rand"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/* static/*
var content embed.FS

type User struct {
	Username    string
	PrivKey     [32]byte
	PubKey      [32]byte
	Color       string
	ShadowUntil time.Time
	ActiveRoom  string
}

type Message struct {
	Sender      string
	Target      string
	Content     string
	Timestamp   time.Time
	IsEncrypted bool
	Color       string
	Signature   string
}

var (
	users       = make(map[string]*User)
	sessions    = make(map[string]string)
	chatHistory []Message
	serverLogs  []string
	mu          sync.RWMutex
)

// addLog verwendet mu.Lock().
func addLog(category, message string) {
	mu.Lock()
	defer mu.Unlock()
	timestamp := time.Now().Format("15:04:05.000")
	entry := fmt.Sprintf("[%s] %-10s | %s", timestamp, category, message)
	serverLogs = append(serverLogs, entry)

	if len(serverLogs) > 200 {
		serverLogs = serverLogs[1:]
	}
}

func encrypt(sharedSecret []byte, text string) string {
	res, err := encryptFull(sharedSecret, text)
	if err != nil {
		return "[Encryption Error]"
	}
	return res
}

func decrypt(sharedSecret []byte, hexText string) string {
	res, err := decryptFull(sharedSecret, hexText)
	if err != nil {
		return "[Integritätsfehler]"
	}
	return res
}

func main() {
	tmpl := template.Must(template.ParseFS(content, "templates/*.html"))
	StartRoomCleanup()

	go func() {
		for {
			time.Sleep(1 * time.Minute)
			mu.Lock()
			cutoff := time.Now().Add(-12 * time.Hour)
			var updated []Message
			for _, m := range chatHistory {
				if m.Timestamp.After(cutoff) {
					updated = append(updated, m)
				}
			}
			chatHistory = updated
			mu.Unlock()
			addLog("SYSTEM", "Routine cleanup: Old messages purged.")
		}
	}()

	http.Handle("/static/", http.FileServer(http.FS(content)))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}

		var onlineNames []string
		for _, u := range users {
			onlineNames = append(onlineNames, u.Username)
		}
		onlineString := myJoin(onlineNames, ", ")

		var uname, ucol string
		if currentUser != nil {
			uname = currentUser.Username
			ucol = currentUser.Color
		}
		mu.RUnlock()

		tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
			"Username":    uname,
			"UserColor":   ucol,
			"OnlineUsers": onlineString,
		})
	})

	http.HandleFunc("/server-logs", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		logsCopy := make([]string, len(serverLogs))
		copy(logsCopy, serverLogs)
		mu.RUnlock()

		reversedLogs := make([]string, len(logsCopy))
		for i := 0; i < len(logsCopy); i++ {
			reversedLogs[i] = logsCopy[len(logsCopy)-1-i]
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><meta http-equiv='refresh' content='2'><style>body{background:#000;color:#0f0;font-family:monospace;font-size:12px;margin:10px;overflow-x:hidden;} .crypto{color:#f0f;} .auth{color:#0af;} .msg{color:#ff0;}</style></head><body>")

		for _, l := range reversedLogs {
			class := ""
			if myContains(l, "CRYPTO") {
				class = "class='crypto'"
			}
			if myContains(l, "AUTH") {
				class = "class='auth'"
			}
			if myContains(l, "MSG") {
				class = "class='msg'"
			}
			if myContains(l, "ADMIN") {
				class = "style='color:#f00;font-weight:bold;'"
			}
			fmt.Fprintf(w, "<div %s>%s</div>", class, l)
		}
		fmt.Fprint(w, "</body></html>")
	})

	http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}
		mu.RUnlock()

		var rawHistory []Message

		if currentUser != nil && currentUser.ActiveRoom != "" {
			roomsMu.RLock()
			room, exists := rooms[currentUser.ActiveRoom]
			roomsMu.RUnlock()

			if exists {
				room.Mu.RLock()
				rawHistory = make([]Message, len(room.Messages))
				copy(rawHistory, room.Messages)
				room.Mu.RUnlock()
			}
		} else {
			mu.RLock()
			rawHistory = make([]Message, len(chatHistory))
			copy(rawHistory, chatHistory)
			mu.RUnlock()
		}

		var filtered []Message
		for _, m := range rawHistory {
			show := false
			if !m.IsEncrypted {
				show = true
			} else if currentUser != nil {
				if m.Sender == currentUser.Username || m.Target == currentUser.Username {
					show = true
				}
			}

			mu.RLock()
			senderUser, senderExists := users[m.Sender]
			mu.RUnlock()

			if senderExists && time.Now().Before(senderUser.ShadowUntil) {
				if currentUser == nil || currentUser.Username != m.Sender {
					show = false
				}
			}

			if show {
				if m.IsEncrypted && currentUser != nil {
					var partnerName string
					if m.Sender == currentUser.Username {
						partnerName = m.Target
					} else {
						partnerName = m.Sender
					}

					mu.RLock()
					partner, exists := users[partnerName]
					mu.RUnlock()

					if exists {
						shared, _ := X25519(currentUser.PrivKey, partner.PubKey)
						m.Content = decrypt(shared[:], m.Content)
					}
				}
				filtered = append(filtered, m)
			}
		}

		reversed := make([]Message, len(filtered))
		for i := 0; i < len(filtered); i++ {
			reversed[i] = filtered[len(filtered)-1-i]
		}

		tmpl.ExecuteTemplate(w, "messages.html", map[string]interface{}{
			"Messages": reversed,
			"Username": func() string {
				if currentUser != nil {
					return currentUser.Username
				}
				return ""
			}(),
		})
	})

	http.HandleFunc("/input", func(w http.ResponseWriter, r *http.Request) {
		tmpl.ExecuteTemplate(w, "input.html", nil)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		name := myTrimSpace(r.FormValue("username"))
		color := r.FormValue("color")

		roomMode := r.FormValue("mode")
		roomName := r.FormValue("room_name")
		roomPass := r.FormValue("room_password")

		if name == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		assignedRoom := ""
		if roomMode == "private" && roomName != "" {
			room, err := GetOrCreateRoom(roomName, roomPass)
			if err != nil {
				addLog("AUTH", "Room Access Denied (Wrong PW): "+roomName)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			assignedRoom = room.Name
		}

		if name == "stk" {
			tmpl.ExecuteTemplate(w, "admin_login.html", map[string]string{"Color": color})
			return
		}

		addLog("AUTH", "Generating X25519 keypair for: "+name)
		priv, pub := GenerateKeyPair()

		mu.Lock()
		users[name] = &User{
			Username:   name,
			PrivKey:    priv,
			PubKey:     pub,
			Color:      color,
			ActiveRoom: assignedRoom,
		}

		sessionBytes := make([]byte, 32)
		rand.Read(sessionBytes)
		sid := myHexEncode(sessionBytes)
		sessions[sid] = name
		mu.Unlock()

		addLog("AUTH", "Session created for "+name+" in room: "+assignedRoom)

		welcomeMsg := Message{
			Sender: "SYSTEM", Target: "all",
			Content:   fmt.Sprintf("Hello %s!\nWelcome to vincere.\nPlease note: No CSAM. No spamming.", name),
			Timestamp: time.Now(), IsEncrypted: false, Color: "#fff762",
		}

		if assignedRoom != "" {
			roomsMu.RLock()
			r := rooms[assignedRoom]
			roomsMu.RUnlock()
			r.Mu.Lock()
			r.Messages = append(r.Messages, welcomeMsg)
			r.Mu.Unlock()
		} else {
			mu.Lock()
			chatHistory = append(chatHistory, welcomeMsg)
			mu.Unlock()
		}

		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	http.HandleFunc("/login-admin", func(w http.ResponseWriter, r *http.Request) {
		pass := r.FormValue("password")
		color := r.FormValue("color")
		adminPassHash := "$2a$12$ajTLsLTyzkF376/Jrme28O.5GlvFMR3qEGVU4GnSE0iiOFTHO9Ka."

		if err := bcrypt.CompareHashAndPassword([]byte(adminPassHash), []byte(pass)); err == nil {
			name := "stk"
			addLog("AUTH", "Admin verification successful for: "+name)
			priv, pub := GenerateKeyPair()
			mu.Lock()
			users[name] = &User{Username: name, PrivKey: priv, PubKey: pub, Color: color}
			sessionBytes := make([]byte, 32)
			rand.Read(sessionBytes)
			sid := myHexEncode(sessionBytes)
			sessions[sid] = name
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true})
			http.Redirect(w, r, "/", http.StatusSeeOther)
		} else {
			addLog("AUTH", "FAILED Admin login attempt!")
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}

		mu.RLock()
		senderName := sessions[cookie.Value]
		sender, ok := users[senderName]
		mu.RUnlock()

		if !ok {
			http.Redirect(w, r, "/input", http.StatusSeeOther)
			return
		}

		text := myTrimSpace(r.FormValue("text"))
		if text != "" {
			if senderName == "stk" && myHasPrefix(text, "/shadow ") {
				targetToShadow := myTrimPrefix(text, "/shadow ")
				mu.Lock()
				if u, exists := users[targetToShadow]; exists {
					u.ShadowUntil = time.Now().Add(12 * time.Hour)
					addLog("ADMIN", "stk shadow-banned user: "+targetToShadow)
				}
				mu.Unlock()
				http.Redirect(w, r, "/input", http.StatusSeeOther)
				return
			}

			if senderName == "stk" && myHasPrefix(text, "/unshadow ") {
				targetToUnshadow := myTrimPrefix(text, "/unshadow ")
				mu.Lock()
				if u, exists := users[targetToUnshadow]; exists {
					u.ShadowUntil = time.Time{}
				}
				mu.Unlock()
				addLog("ADMIN", "stk removed shadow-ban for: "+targetToUnshadow)
				http.Redirect(w, r, "/input", http.StatusSeeOther)
				return
			}

			msg := Message{Sender: senderName, Content: text, Timestamp: time.Now(), Target: "all", Color: sender.Color}

			if myHasPrefix(text, "@") {
				parts := mySplitN(text, " ", 2)
				targetName := myTrimPrefix(parts[0], "@")
				mu.RLock()
				target, exists := users[targetName]
				mu.RUnlock()

				if exists && len(parts) > 1 {
					addLog("CRYPTO", fmt.Sprintf("Initiating E2EE: %s -> %s", senderName, targetName))
					shared, _ := X25519(sender.PrivKey, target.PubKey)
					msg.Content = encrypt(shared[:], parts[1])
					msg.Target = targetName
					msg.IsEncrypted = true
					addLog("MSG", "IGE E2EE stored.")
				} else {
					addLog("MSG", "Public message from "+senderName)
				}
			} else {
				addLog("MSG", "Public message from "+senderName)
			}

			roomName := sender.ActiveRoom
			var targetHistory *[]Message
			var historyMu *sync.RWMutex

			if roomName != "" {
				roomsMu.RLock()
				r, exists := rooms[roomName]
				roomsMu.RUnlock()
				if exists {
					targetHistory = &r.Messages
					historyMu = &r.Mu
					r.Mu.Lock()
					r.LastActivity = time.Now()
					r.Mu.Unlock()
				}
			} else {
				targetHistory = &chatHistory
				historyMu = &mu
			}

			var base [32]byte
			base[0] = 9
			proof, _ := X25519(sender.PrivKey, base)
			h := hmac.New(NewSHA256, proof[:])
			h.Write([]byte(msg.Content))
			msg.Signature = myHexEncode(h.Sum(nil))

			historyMu.Lock()
			*targetHistory = append(*targetHistory, msg)
			historyMu.Unlock()
		}
		http.Redirect(w, r, "/input", http.StatusSeeOther)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err == nil {
			sid := cookie.Value
			mu.Lock()
			name, ok := sessions[sid]
			if ok {
				delete(users, name)
				delete(sessions, sid)
			}
			mu.Unlock()

			if ok {
				addLog("AUTH", "User logout: "+name)
			}
		}

		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	fmt.Println("vincere messenger running.")
	fmt.Println("Address: http://127.0.0.1:8080")
	addLog("SYSTEM", "Server started on :8080")
	http.ListenAndServe(":8080", nil)
}
