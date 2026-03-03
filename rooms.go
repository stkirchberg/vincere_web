package main

import (
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Room struct {
	Name         string
	PasswordHash string
	Messages     []Message
	LastActivity time.Time
	Mu           sync.RWMutex
}

var (
	rooms   = make(map[string]*Room)
	roomsMu sync.RWMutex
)

func StartRoomCleanup() {
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			roomsMu.Lock()
			cutoff := time.Now().Add(-12 * time.Hour)
			for name, r := range rooms {
				r.Mu.RLock()
				inactive := r.LastActivity.Before(cutoff)
				r.Mu.RUnlock()

				if inactive {
					delete(rooms, name)
					addLog("ADMIN", "Room deleted due to 12h inactivity: "+name)
				}
			}
			roomsMu.Unlock()
		}
	}()
}

func GetOrCreateRoom(name, password string) (*Room, error) {
	roomsMu.Lock()
	defer roomsMu.Unlock()

	r, exists := rooms[name]
	if !exists {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		newRoom := &Room{
			Name:         name,
			PasswordHash: string(hash),
			Messages:     []Message{},
			LastActivity: time.Now(),
		}
		rooms[name] = newRoom
		addLog("ADMIN", "New private room created: "+name)
		return newRoom, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(r.PasswordHash), []byte(password))
	if err != nil {
		return nil, err
	}

	return r, nil
}
