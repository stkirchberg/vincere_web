package main

import (
	"crypto/hmac"
	"crypto/rand"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"

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
	LastSeen    time.Time
}

type Message struct {
	Sender      string
	Target      string
	Content     string
	Timestamp   time.Time
	IsEncrypted bool
	Color       string
	Signature   string
	IsShadowed  bool
}

var (
	users          = make(map[string]*User)
	sessions       = make(map[string]string)
	publicKeyStore = make(map[string][32]byte)
	chatHistory    []Message
	serverLogs     []string
	mu             sync.RWMutex
	logMu          sync.Mutex
)

func addLog(category, message string) {
	logMu.Lock()
	defer logMu.Unlock()

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
		return "[Integrity Error]"
	}
	return res
}

func main() {
	godotenv.Load()
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

		var onlineList []*User
		for _, u := range users {
			if currentUser != nil {
				if u.ActiveRoom == currentUser.ActiveRoom {
					onlineList = append(onlineList, u)
				}
			} else {
				if u.ActiveRoom == "" {
					onlineList = append(onlineList, u)
				}
			}
		}

		var uname, ucol, uroom string
		if currentUser != nil {
			uname = currentUser.Username
			ucol = currentUser.Color
			uroom = currentUser.ActiveRoom
		}

		if uroom == "" {
			uroom = "Public Room"
		}
		mu.RUnlock()

		tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
			"Username":    uname,
			"UserColor":   ucol,
			"OnlineUsers": onlineList,
			"RoomName":    uroom,
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
		mu.Lock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
				if currentUser != nil {
					currentUser.LastSeen = time.Now()
				}
			}
		}
		mu.Unlock()

		var rawHistory []Message
		isInPrivateRoom := currentUser != nil && currentUser.ActiveRoom != ""

		if isInPrivateRoom {
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

			if m.IsShadowed {
				if currentUser == nil || currentUser.Username != m.Sender {
					show = false
				}
			}

			if show {
				if m.IsEncrypted && currentUser != nil {
					partnerName := m.Target
					if m.Target == currentUser.Username {
						partnerName = m.Sender
					}
					mu.RLock()
					partnerPubKey, exists := publicKeyStore[partnerName]
					mu.RUnlock()

					if exists {
						shared, _ := X25519(currentUser.PrivKey, partnerPubKey)
						m.Content = decrypt(shared[:], m.Content)
					} else {
						m.Content = "[Error: Partner's public key not found]"
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
			room, err := GetOrCreateRoom(roomName, roomPass, name)
			if err != nil {
				addLog("AUTH", "Room Access Denied (Wrong PW): "+roomName)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			assignedRoom = room.Name
		}

		if name == "stk" {
			tmpl.ExecuteTemplate(w, "admin_login.html", map[string]string{
				"Color":        color,
				"RoomName":     roomName,
				"RoomPassword": roomPass,
				"RoomMode":     roomMode,
			})
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
			LastSeen:   time.Now(),
		}

		sessionBytes := make([]byte, 32)
		rand.Read(sessionBytes)
		sid := myHexEncode(sessionBytes)
		sessions[sid] = name
		publicKeyStore[name] = pub
		mu.Unlock()

		if assignedRoom != "" {
			addLog("AUTH", "Session created for "+name+" in private room")
		} else {
			addLog("AUTH", "Session created for "+name+" in public chat")
		}

		var welcomeContent string
		if assignedRoom != "" {
			welcomeContent = fmt.Sprintf("Hello %s!\nYou are in a private room. Access only via name+pw.\nUse @username for E2EE.\nEverything is private. No CSAM.", name)
		} else {
			welcomeContent = fmt.Sprintf("Hello %s!\nWelcome to vincere.\nPlease note: No CSAM. No spamming.", name)
		}

		welcomeMsg := Message{
			Sender:      "SYSTEM",
			Target:      "all",
			Content:     welcomeContent,
			Timestamp:   time.Now(),
			IsEncrypted: false,
			Color:       "#fff762",
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

		roomMode := r.FormValue("mode")
		roomName := r.FormValue("room_name")
		roomPass := r.FormValue("room_password")

		adminPassHash := os.Getenv("ADMIN_HASH")

		if err := bcrypt.CompareHashAndPassword([]byte(adminPassHash), []byte(pass)); err == nil {
			name := "stk"

			assignedRoom := ""
			if roomMode == "private" && roomName != "" {
				room, err := GetOrCreateRoom(roomName, roomPass, name)
				if err != nil {
					addLog("AUTH", "Admin Room Access Denied: "+roomName)
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
				assignedRoom = room.Name
			}

			addLog("AUTH", "Admin verification successful: "+name)
			priv, pub := GenerateKeyPair()

			mu.Lock()
			users[name] = &User{
				Username:   name,
				PrivKey:    priv,
				PubKey:     pub,
				Color:      color,
				ActiveRoom: assignedRoom,
				LastSeen:   time.Now(),
			}

			sessionBytes := make([]byte, 32)
			rand.Read(sessionBytes)
			sid := myHexEncode(sessionBytes)
			sessions[sid] = name
			publicKeyStore[name] = pub
			mu.Unlock()

			adminWelcome := Message{
				Sender:      "SYSTEM",
				Target:      "all",
				Content:     "The creator stk has entered the arena! \nBow to your admin!",
				Timestamp:   time.Now(),
				IsEncrypted: false,
				Color:       "#fff762",
			}

			if assignedRoom != "" {
				roomsMu.RLock()
				r := rooms[assignedRoom]
				roomsMu.RUnlock()
				r.Mu.Lock()
				r.Messages = append(r.Messages, adminWelcome)
				r.Mu.Unlock()
			} else {
				mu.Lock()
				chatHistory = append(chatHistory, adminWelcome)
				mu.Unlock()
			}

			http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
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
				u, exists := users[targetToShadow]
				if exists {
					u.ShadowUntil = time.Now().Add(12 * time.Hour)
				}
				mu.Unlock()

				if exists {
					addLog("ADMIN", "stk shadow-banned user: "+targetToShadow)
				}
				http.Redirect(w, r, "/input", http.StatusSeeOther)
				return
			}

			if senderName == "stk" && myHasPrefix(text, "/unshadow ") {
				targetToUnshadow := myTrimPrefix(text, "/unshadow ")
				mu.Lock()
				u, exists := users[targetToUnshadow]
				if exists {
					u.ShadowUntil = time.Time{}
				}
				mu.Unlock()

				if exists {
					addLog("ADMIN", "stk removed shadow-ban for: "+targetToUnshadow)
				}
				http.Redirect(w, r, "/input", http.StatusSeeOther)
				return
			}

			msg := Message{
				Sender:     senderName,
				Content:    text,
				Timestamp:  time.Now(),
				Target:     "all",
				Color:      sender.Color,
				IsShadowed: time.Now().Before(sender.ShadowUntil),
			}

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
				}
			}

			var base [32]byte
			base[0] = 9
			proof, _ := X25519(sender.PrivKey, base)
			h := hmac.New(NewSHA256, proof[:])
			h.Write([]byte(msg.Content))
			msg.Signature = myHexEncode(h.Sum(nil))

			if sender.ActiveRoom != "" {
				roomsMu.RLock()
				r, exists := rooms[sender.ActiveRoom]
				roomsMu.RUnlock()

				if exists {
					r.Mu.Lock()
					r.Messages = append(r.Messages, msg)
					r.LastActivity = time.Now()
					r.Mu.Unlock()
					addLog("MSG", fmt.Sprintf("Private room: Message from %s", senderName))
				}
			} else {
				mu.Lock()
				chatHistory = append(chatHistory, msg)
				mu.Unlock()
				addLog("MSG", "Public message from "+senderName)
			}
		}
		http.Redirect(w, r, "/input", http.StatusSeeOther)
	})

	go func() {
		for {
			time.Sleep(30 * time.Second)
			mu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			for name, u := range users {
				if u.LastSeen.Before(cutoff) {
					delete(users, name)
					addLog("AUTH", "Timeout: "+name+" removed.")
				}
			}
			mu.Unlock()
		}
	}()

	http.HandleFunc("/online-frame", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		var currentUser *User
		if cookie, err := r.Cookie("session_id"); err == nil {
			if name, ok := sessions[cookie.Value]; ok {
				currentUser = users[name]
			}
		}

		var onlineList []*User
		for _, u := range users {
			if currentUser != nil && u.ActiveRoom == currentUser.ActiveRoom {
				onlineList = append(onlineList, u)
			} else if currentUser == nil && u.ActiveRoom == "" {
				onlineList = append(onlineList, u)
			}
		}
		mu.RUnlock()

		tmpl.ExecuteTemplate(w, "online.html", map[string]interface{}{
			"OnlineUsers": onlineList,
		})
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
