package main

import (
	"fmt"
	forum "forum/Functions"
	"html/template"
	"net/http"

	"github.com/gorilla/sessions" // go get github.com/gorilla/sessions
)

var (
	store = sessions.NewCookieStore([]byte("something-very-secret"))
)

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {

	tmplPath := fmt.Sprintf("templates/%s.html", tmpl)
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Erreur lors du chargement du template : "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Erreur lors de l'exécution du template : "+err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	// Servir les fichiers statiques (CSS, JS, images)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Route pour la page d'accueil
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/mytripy-non", http.StatusFound)
	})

	// Routes pour les pages HTML
	http.HandleFunc("/mytripy-non", forum.MyTripyNonHandler)

	http.HandleFunc("/apropos", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "apropos", nil)
	})

	http.HandleFunc("/mentions-legales", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "mentions-legales", nil)
	})

	http.HandleFunc("/SeConnecter", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			forum.CheckCredentialsForConnection(w, r)
			session, _ := store.Get(r, "session")
			session.Values["user"] = r.FormValue("username")
			session.Save(r, w)
			http.Redirect(w, r, "/profil", http.StatusFound)
		} else {
			renderTemplate(w, "SeConnecter", nil)
		}
	})

	http.HandleFunc("/CreerCompte", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			forum.CreateUser(w, r)
		} else {
			renderTemplate(w, "CreerCompte", nil)
		}
	})

	http.HandleFunc("/mot-de-passe-oublie", func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "mot-de-passe-oublie", nil)
	})

	http.HandleFunc("/profil", forum.ProfilPage)
	http.HandleFunc("/updateProfile", forum.UpdateProfile)
	http.HandleFunc("/updateAvatar", forum.UpdateAvatar)
	http.HandleFunc("/destinations", forum.AllRegions)

	http.HandleFunc("/like", forum.LikeHandler)
	http.HandleFunc("/likechat", forum.LikeChatHandler)
	http.HandleFunc("/like-message", forum.LikeMessageHandler)

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")
		session.Options.MaxAge = -1
		session.Save(r, w)
		forum.Logout(w, r)
	})

	http.HandleFunc("/search", forum.SearchSuggestionsHandler)

	http.HandleFunc("/welcome", forum.FileDiscussion)
	http.HandleFunc("/create-chat", forum.CreateChatHandler)
	http.HandleFunc("/select-chat", forum.SelectChatHandler)
	http.HandleFunc("/fetch-chats", forum.FetchChatsHandler)

	http.HandleFunc("/chat_messages", forum.FilMessagesHandler)
	http.HandleFunc("/send-message", forum.SendMessageHandler)
	http.HandleFunc("/fetch-messages", forum.FetchMessagesHandler)

	http.HandleFunc("/region", forum.RegionHandler)

	// Démarrer le serveur
	fmt.Println("Serveur lancé sur http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Erreur lors du lancement du serveur :", err)
	}
}
