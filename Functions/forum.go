package forum

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Exporter le magasin de sessions
var (
	Store = sessions.NewCookieStore([]byte("votre-clé-secrète"))
	db    *sql.DB
)

// renvoie les message d'erreur
func renderError(w http.ResponseWriter, tmpl string, errorMsg string) {
	t, err := template.ParseFiles(fmt.Sprintf("templates/%s.html", tmpl))
	if err != nil {
		http.Error(w, "Erreur lors du chargement du template : "+err.Error(), http.StatusInternalServerError)
		return
	}
	data := struct {
		ErrorMessage string
	}{
		ErrorMessage: errorMsg,
	}

	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Erreur lors de l'exécution du template : "+err.Error(), http.StatusInternalServerError)
	}
}

// Regarde si l'utilisateur existe (ce l'ho già nell'altra pero non è uguale)
func CheckUserExists(db *sql.DB, email, pseudo string) (bool, bool, error) {
	var emailExists, pseudoExists bool
	var id int

	err := db.QueryRow("SELECT rowid FROM User WHERE EMAIL = ?", email).Scan(&id)
	if err == nil {
		emailExists = true
	} else if err != sql.ErrNoRows {
		return false, false, err
	}

	err = db.QueryRow("SELECT rowid FROM User WHERE USERNAME = ?", pseudo).Scan(&id)
	if err == nil {
		pseudoExists = true
	} else if err != sql.ErrNoRows {
		return false, false, err
	}

	return emailExists, pseudoExists, nil
}

// guarda se il password dato va bene (con numer, maiuscule, minuscule, caratteri speciali)
func isValidPassword(password string) bool {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(password) >= 6 {
		hasMinLen = true
	}
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case regexp.MustCompile(`[!@#~$%^&*()_+|<>?:{}]`).MatchString(string(char)):
			hasSpecial = true
		}
	}
	return hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
}

// prende info date dalla creazione del account e le mette nella database (ce l'ho già ma non è uguale)
func CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	pseudo := r.FormValue("pseudo")
	motDePasse := r.FormValue("mot_de_passe")
	confirmeMotDePasse := r.FormValue("confirme_mot_de_passe")
	photoURL := r.FormValue("photo_url") // Récupérer l'URL de l'avatar choisi

	// Validation du format de l'email
	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailPattern.MatchString(email) {
		renderError(w, "CreerCompte", "L'adresse email est invalide.")
		return
	}

	if motDePasse != confirmeMotDePasse {
		renderError(w, "CreerCompte", "Les mots de passe ne correspondent pas.")
		return
	}

	if !isValidPassword(motDePasse) {
		renderError(w, "CreerCompte", "Le mot de passe doit contenir au minimum\nune majuscule, une minuscule, un caractère spécial, un chiffre, et au minimum 6 caractères.")
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "CreerCompte", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	emailExists, pseudoExists, err := CheckUserExists(db, email, pseudo)
	if err != nil {
		renderError(w, "CreerCompte", "Erreur lors de la vérification des utilisateurs existants.")
		return
	}
	if emailExists {
		renderError(w, "CreerCompte", "L'email est déjà utilisé.")
		return
	}
	if pseudoExists {
		renderError(w, "CreerCompte", "Le pseudo est déjà utilisé.")
		return
	}

	motDePasseChiffre, err := bcrypt.GenerateFromPassword([]byte(motDePasse), bcrypt.DefaultCost)
	if err != nil {
		renderError(w, "CreerCompte", "Erreur lors du chiffrement du mot de passe.")
		return
	}

	// Utilisez l'URL de l'avatar choisi ou une URL de photo par défaut
	if photoURL == "" {
		photoURL = "static/img/avatar/avatarFemme1.png"
	} else {
		photoURL = strings.TrimPrefix(photoURL, "http://localhost:8080/")
	}

	biographie := ""

	_, err = db.Exec("INSERT INTO User (USERNAME, PASSWORD, EMAIL, PHOTO_URL, BIOGRAPHY) VALUES (?, ?, ?, ?, ?)", pseudo, motDePasseChiffre, email, photoURL, biographie)
	if err != nil {
		renderError(w, "CreerCompte", "Erreur lors de la création du compte.")
		return
	}

	// Créer une nouvelle session et stocker le nom d'utilisateur
	session, _ := Store.Get(r, "session-name")
	session.Values["username"] = pseudo
	session.Save(r, w)

	// Rediriger vers la page mytripy-non après la création du compte
	http.Redirect(w, r, "/mytripy-non", http.StatusFound)
}

// guarda che le credentials sono giuste per connessione (c'è ma non è uguale)
func CheckCredentialsForConnection(w http.ResponseWriter, r *http.Request) {
	var hashedPassword string
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "SeConnecter", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	err = db.QueryRow("SELECT PASSWORD FROM User WHERE USERNAME = ?", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			renderError(w, "SeConnecter", "Mot de passe ou identifiants introuvables")
		} else {
			http.Error(w, "Erreur interne lors de la vérification des identifiants : "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		renderError(w, "SeConnecter", "Mot de passe ou identifiants introuvables")
		return
	}

	// Créer une nouvelle session et stocker le nom d'utilisateur
	session, _ := Store.Get(r, "session-name")
	session.Values["username"] = username
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfilPage(w http.ResponseWriter, r *http.Request) {
	type Region struct {
		RegionName  string `json:"region_name"`
		RegionImg   string `json:"region_imgurl"`
		RegionDescr string `json:"region_description"`
	}

	type ChatInfo struct {
		Name         string `json:"name"`
		MessageCount int    `json:"message_count"`
		Description  string `json:"description"`
		PhotoURL     string `json:"photo_url"`
		Username     string `json:"username"`
	}

	type LikedChat struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		MessageCount int    `json:"message_count"`
		PhotoURL     string `json:"photo_url"`
		Creator      string `json:"creator"`
	}

	var connected bool
	session, _ := Store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)

	if !ok {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		http.Error(w, "Erreur d'ouverture de la base de données.", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Fetch user data
	var pseudo, urlPhoto, biography string
	err = db.QueryRow("SELECT USERNAME, PHOTO_URL, BIOGRAPHY FROM User WHERE USERNAME = ?", username).Scan(&pseudo, &urlPhoto, &biography)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des informations utilisateur : "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch liked regions
	queryRegions := `
        SELECT Region.REGION_NAME, Region.REGION_IMG_URL, Region.DESCRI
        FROM Region
        JOIN USER_LIKES ON Region.REGION_NAME = USER_LIKES.REGION_NAME
        WHERE USER_LIKES.USER_ID = ? AND USER_LIKES.LIKED = TRUE;
    `
	rowsRegions, err := db.Query(queryRegions, username)
	if err != nil {
		fmt.Println("Error executing query:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rowsRegions.Close()

	var regions []Region
	for rowsRegions.Next() {
		var region Region
		err := rowsRegions.Scan(&region.RegionName, &region.RegionImg, &region.RegionDescr)
		if err != nil {
			fmt.Println("Error scanning row:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		regions = append(regions, region)
	}

	// Check for errors after iteration
	if err = rowsRegions.Err(); err != nil {
		fmt.Println("Error during row iteration:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch chats created by the connected user
	queryChats := `
        SELECT c.name, COUNT(m.id) AS message_count, c.descri, u.PHOTO_URL, u.USERNAME
        FROM chats c
        LEFT JOIN messages m ON c.name = m.chat_name
        LEFT JOIN User u ON c.creator = u.USERNAME
        WHERE c.creator = ? -- Only chats created by the connected user
        GROUP BY c.name, c.descri, u.PHOTO_URL, u.USERNAME;
    `
	rowsChats, err := db.Query(queryChats, username)
	if err != nil {
		fmt.Println("Error executing chat query:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rowsChats.Close()

	var chats []ChatInfo
	for rowsChats.Next() {
		var chat ChatInfo
		err := rowsChats.Scan(&chat.Name, &chat.MessageCount, &chat.Description, &chat.PhotoURL, &chat.Username)
		if err != nil {
			fmt.Println("Error scanning chat row:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		chats = append(chats, chat)
	}

	// Check for errors after iteration
	if err = rowsChats.Err(); err != nil {
		fmt.Println("Error during chat row iteration:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Fetch chats liked by the user
	queryLikedChats := `
       SELECT c.name, COUNT(m.id) AS message_count, c.descri, u.PHOTO_URL, u.USERNAME AS creator
FROM chats c
LEFT JOIN messages m ON c.name = m.chat_name
LEFT JOIN Chat_Liked cl ON c.name = cl.chatID
LEFT JOIN User u ON c.creator = u.USERNAME
WHERE cl.Username = ? AND cl.liked = TRUE
GROUP BY c.name, c.descri, u.PHOTO_URL, u.USERNAME;


    `
	rowsLikedChats, err := db.Query(queryLikedChats, username)
	if err != nil {
		fmt.Println("Error executing liked chat query:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rowsLikedChats.Close()

	var likedChats []LikedChat
	for rowsLikedChats.Next() {
		var likedChat LikedChat
		err := rowsLikedChats.Scan(&likedChat.Name, &likedChat.MessageCount, &likedChat.Description, &likedChat.PhotoURL, &likedChat.Creator)
		if err != nil {
			fmt.Println("Error scanning liked chat row:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		likedChats = append(likedChats, likedChat)
	}

	// Check for errors after iteration
	if err = rowsLikedChats.Err(); err != nil {
		fmt.Println("Error during liked chat row iteration:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check session state
	connected = ok && username != ""

	// Prepare data for the template
	data := struct {
		Pseudo      string
		PhotoURL    string
		Biography   string
		IsConnected bool
		Regions     []Region
		Chats       []ChatInfo
		LikedChats  []LikedChat
	}{
		Pseudo:      pseudo,
		PhotoURL:    urlPhoto,
		Biography:   biography,
		IsConnected: connected,
		Regions:     regions,
		Chats:       chats,
		LikedChats:  likedChats,
	}

	// Render the template
	t, err := template.ParseFiles("templates/profil.html")
	if err != nil {
		http.Error(w, "Erreur lors du chargement du template : "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Erreur lors de l'exécution du template : "+err.Error(), http.StatusInternalServerError)
	}
}

func UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	type ProfileData struct {
		Pseudo string `json:"pseudo"`
		Bio    string `json:"bio"`
	}

	var data ProfileData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Erreur de décodage JSON", http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE User SET BIOGRAPHY = ? WHERE USERNAME = ?;`,
		data.Bio, data.Pseudo)

	// Répondre avec un message de succès
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Profil mis à jour avec succès !"))
}

func UpdateAvatar(w http.ResponseWriter, r *http.Request) {
	// Ensure the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	type AvatarData struct {
		Avatar string `json:"avatar"`
	}

	// Decode the JSON request body
	var data AvatarData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Erreur lors du décodage du corps de la requête", http.StatusBadRequest)
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	// Validate the avatar URL
	if data.Avatar == "" {
		http.Error(w, "URL d'avatar non valide ou vide", http.StatusBadRequest)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec(`UPDATE User SET PHOTO_URL = ? WHERE USERNAME = ?;`,
		data.Avatar, username)

	// Simulate storing the avatar URL (e.g., in a database)
	// Example: storeAvatarInDatabase(data.Avatar)

	// Respond with a success message
	response := map[string]string{
		"message": "Avatar mis à jour avec succès !",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// deconessione dalla sessione, questo c'è ma non è uguale
func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session-name")
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/mytripy-non", http.StatusFound)
}

// /////////////////////////////// LIKES ////////////////////////////////////////////////////////////:
type LikeRequest struct {
	Region string `json:"region"` // Region name from the client
	Liked  bool   `json:"liked"`  // Liked status from the client
}

func LikeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var likeRequest LikeRequest
	err := json.NewDecoder(r.Body).Decode(&likeRequest)
	if err != nil {
		http.Error(w, "Bad request: Unable to parse JSON", http.StatusBadRequest)
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Check if the user already liked this region
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM USER_LIKES WHERE USER_ID = ? AND REGION_NAME = ?);`
	err = db.QueryRow(query, username, likeRequest.Region).Scan(&exists)
	if err != nil {
		fmt.Println("Error checking existing like:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if exists {
		// Update the existing like record
		_, err = db.Exec(`UPDATE USER_LIKES SET LIKED = ? WHERE USER_ID = ? AND REGION_NAME = ?;`,
			likeRequest.Liked, username, likeRequest.Region)
	} else {
		// Insert a new like record
		_, err = db.Exec(`INSERT INTO USER_LIKES (USER_ID, REGION_NAME, LIKED) VALUES (?, ?, ?);`,
			username, likeRequest.Region, likeRequest.Liked)
	}

	if err != nil {
		fmt.Println("Error executing SQL query:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Region '%s' liked status updated by user %d: %t", likeRequest.Region, username, likeRequest.Liked),
	})
}

type LikeChatRequest struct {
	Chat  string `json:"region"` // Region name from the client
	Liked bool   `json:"liked"`  // Liked status from the client
}

func LikeChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var likeChatRequest LikeChatRequest
	err := json.NewDecoder(r.Body).Decode(&likeChatRequest)
	if err != nil {
		http.Error(w, "Bad request: Unable to parse JSON", http.StatusBadRequest)
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		fmt.Println("Error opening database:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Check if the user already liked this region
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM Chat_Liked WHERE Username = ? AND chatID = ?);`
	err = db.QueryRow(query, username, likeChatRequest.Chat).Scan(&exists)
	if err != nil {
		fmt.Println("Error checking existing like:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if exists {
		// Update the existing like record
		_, err = db.Exec(`UPDATE Chat_Liked SET LIKED = ? WHERE Username = ? AND chatID = ?;`,
			likeChatRequest.Liked, username, likeChatRequest.Chat)
	} else {
		// Insert a new like record
		_, err = db.Exec(`INSERT INTO Chat_Liked (Username, chatID, LIKED) VALUES (?, ?, ?);`,
			username, likeChatRequest.Chat, likeChatRequest.Liked)
	}

	if err != nil {
		fmt.Println("Error executing SQL query:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Chat '%s' liked status updated by user %d: %t", likeChatRequest.Chat, username, likeChatRequest.Liked),
	})
}

func LikeMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var likeData struct {
		MessageID int  `json:"message_id"`
		Liked     bool `json:"liked"`
	}

	err := json.NewDecoder(r.Body).Decode(&likeData)
	if err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, `{"error": "Unauthorized. Please log in."}`, http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Println("Error opening database:", err)
		http.Error(w, `{"error": "Internal server error"}`, http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}
	defer db.Close()

	// Check if the user already liked this message
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM Msg_Liked WHERE Username = ? AND message_id = ?);`
	err = db.QueryRow(query, username, likeData.MessageID).Scan(&exists)
	if err != nil {
		log.Println("Error checking existing like:", err)
		http.Error(w, `{"error": "Internal server error"}`, http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}

	if exists {
		// Update the existing like record
		_, err = db.Exec(`UPDATE Msg_Liked SET LIKED = ? WHERE Username = ? AND message_id = ?;`,
			likeData.Liked, username, likeData.MessageID)
	} else {
		// Insert a new like record
		_, err = db.Exec(`INSERT INTO Msg_Liked (Username, message_id, LIKED) VALUES (?, ?, ?);`,
			username, likeData.MessageID, likeData.Liked)
	}

	if err != nil {
		log.Println("Error executing SQL query:", err)
		http.Error(w, `{"error": "Database error occurred"}`, http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Message ID '%d' liked status updated: %t", likeData.MessageID, likeData.Liked),
	})
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// prende info di cui ha bisogno mytripy-non.html, da ridurre se possibile
func MyTripyNonHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session and username
	session, _ := Store.Get(r, "session-name")
	username, connected := session.Values["username"].(string)

	// Define RegionChat struct
	type RegionChat struct {
		RegionName  string
		ChatCount   int
		RegionImg   string
		RegionDescr string
		RegionLiked bool
	}

	// Prepare data for the template
	data := struct {
		IsConnected bool
		Regions     []RegionChat
	}{
		IsConnected: connected, // Pass connection state to the template
	}

	// Fetch popular regions
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		http.Error(w, "Erreur d'ouverture de la base de données.", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	query := `
        SELECT r.REGION_NAME, 
               COUNT(c.CHAT_NAME) AS CHAT_COUNT, 
               r.REGION_IMG_URL, 
               r.DESCRI,
               COALESCE(ul.LIKED, FALSE) AS LIKED
        FROM Region r
        JOIN Department d ON r.REGION_NAME = d.REGION_NAME
        JOIN Chat c ON d.DEPARTMENT_NAME = c.DEPARTMENT_NAME
        LEFT JOIN USER_LIKES ul ON r.REGION_NAME = ul.REGION_NAME AND ul.USER_ID = ?
        GROUP BY r.REGION_NAME, r.REGION_IMG_URL, r.DESCRI
        ORDER BY CHAT_COUNT DESC
        LIMIT 3;
    `

	rows, err := db.Query(query, username) // Query with user-specific likes (username may be empty)
	if err != nil {
		log.Println("Query error:", err)
		http.Error(w, "Erreur lors de l'exécution de la requête.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var region RegionChat
		if err := rows.Scan(&region.RegionName, &region.ChatCount, &region.RegionImg, &region.RegionDescr, &region.RegionLiked); err != nil {
			http.Error(w, "Erreur lors du scan des résultats.", http.StatusInternalServerError)
			return
		}
		data.Regions = append(data.Regions, region)
	}

	// Render the template with the data
	tmpl, err := template.ParseFiles("templates/mytripy-non.html")
	if err != nil {
		http.Error(w, "Erreur lors du chargement du template : "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Erreur lors de l'exécution du template : "+err.Error(), http.StatusInternalServerError)
	}
}

// AllRegions fetches all regions needed for destinations.html and handles connection state
func AllRegions(w http.ResponseWriter, r *http.Request) {
	session, _ := Store.Get(r, "session-name")
	username, isConnected := session.Values["username"].(string)

	// Define RegionChat struct
	type RegionChat struct {
		RegionName  string
		RegionImg   string
		RegionDescr string
		RegionLiked bool
	}

	// Prepare data for the template
	data := struct {
		IsConnected bool
		Regions     []RegionChat
	}{
		IsConnected: isConnected, // Send connection state to the template
	}

	// Open the database
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		http.Error(w, "Database error.", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Fetch all regions with like status
	query := `
        SELECT Region.REGION_NAME, Region.REGION_IMG_URL, Region.DESCRI, 
        COALESCE(USER_LIKES.LIKED, FALSE) AS LIKED
        FROM Region
        LEFT JOIN USER_LIKES 
        ON Region.REGION_NAME = USER_LIKES.REGION_NAME AND USER_LIKES.USER_ID = ?;
    `
	rows, err := db.Query(query, username) // `username` is empty for unauthenticated users
	if err != nil {
		http.Error(w, "Error querying database.", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var region RegionChat
		if err := rows.Scan(&region.RegionName, &region.RegionImg, &region.RegionDescr, &region.RegionLiked); err != nil {
			http.Error(w, "Error scanning regions.", http.StatusInternalServerError)
			return
		}
		data.Regions = append(data.Regions, region)
	}

	// Render the template
	tmpl, err := template.ParseFiles("templates/destinations.html")
	if err != nil {
		http.Error(w, "Error loading template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
	}
}

func SearchSuggestionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	query := r.URL.Query().Get("q")

	// Check if query length is at least 2 characters
	if len(query) < 2 {
		json.NewEncoder(w).Encode([]map[string]string{}) // Return an empty array if query is too short
		return
	}

	// Database connection (adjust with your own credentials)
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		http.Error(w, "Error opening database", http.StatusInternalServerError)
		fmt.Println("Database connection error:", err)
		return
	}
	defer db.Close()

	// Append wildcards for the LIKE clause
	searchPattern := "%" + query + "%"

	// Prepare the SQL query
	rows, err := db.Query(`
        SELECT D.DEPARTMENT_NAME, R.REGION_NAME
        FROM Department D
        JOIN Region R ON D.REGION_NAME = R.REGION_NAME
        WHERE D.DEPARTMENT_NAME LIKE ? OR R.REGION_NAME LIKE ?
        LIMIT 5;
    `, searchPattern, searchPattern)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Query execution error:", err)
		return
	}
	defer rows.Close()

	// Process the query results
	var filtered []map[string]string
	for rows.Next() {
		var departmentName, regionName string
		if err := rows.Scan(&departmentName, &regionName); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println("Row scan error:", err)
			return
		}
		// Add department and region name as separate fields in the response
		filtered = append(filtered, map[string]string{
			"departmentName": departmentName,
			"regionName":     regionName,
		})
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Println("Rows iteration error:", err)
		return
	}

	// Send the filtered options as JSON response
	json.NewEncoder(w).Encode(filtered)
}

// ///////////////////////////////////////////////// FIL DISCUSSION //////////////////////////////////////////////////
// prende tutte le chat dalla db
func FileDiscussion(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
	}

	username, _ := session.Values["username"].(string)
	region, ok := session.Values["region"].(string)
	if !ok || region == "" {
		http.Redirect(w, r, "/region-selection", http.StatusSeeOther)
		return
	}

	// Open the database
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "CreerCompte", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	// Fetch main chat with total likes and liked status
	queryMain := `
        SELECT 
            c.name AS chat_name, 
            COUNT(m.id) AS message_count, 
            c.descri, 
            r.REGION_IMG_URL, 
            COALESCE(like_counts.total_likes, 0) AS total_likes,
            COALESCE(cl.liked, FALSE) AS user_liked
        FROM 
            chats c
        LEFT JOIN 
            messages m ON c.name = m.chat_name
        LEFT JOIN 
            Region r ON c.region = r.REGION_NAME
        LEFT JOIN (
            SELECT 
                chatID, 
                COUNT(*) AS total_likes
            FROM 
                Chat_Liked
            GROUP BY 
                chatID
        ) like_counts ON c.name = like_counts.chatID
        LEFT JOIN 
            Chat_Liked cl ON c.name = cl.chatID AND cl.Username = ?
        WHERE 
            c.principal = TRUE 
            AND c.region = ?
        GROUP BY 
            c.name, c.descri, r.REGION_IMG_URL, like_counts.total_likes, cl.liked;
    `
	principal, err := db.Query(queryMain, username, region)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer principal.Close()

	type MainChat struct {
		Name         string
		MessageCount int
		Descri       string
		ImageURL     string
		TotalLikes   int
		UserLiked    bool
	}

	var mainChat MainChat
	if principal.Next() {
		err := principal.Scan(&mainChat.Name, &mainChat.MessageCount, &mainChat.Descri, &mainChat.ImageURL, &mainChat.TotalLikes, &mainChat.UserLiked)
		if err != nil {
			http.Error(w, "Failed to scan main chat data", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "No main chat found", http.StatusNotFound)
		return
	}

	// Fetch user chats with total likes and liked status
	queryChats := `
        SELECT 
            c.name AS chat_name, 
            COUNT(m.id) AS message_count, 
            c.descri, 
            u.PHOTO_URL, 
            u.USERNAME, 
            COALESCE(like_counts.total_likes, 0) AS total_likes,
            COALESCE(cl.liked, FALSE) AS user_liked
        FROM 
            chats c
        LEFT JOIN 
            messages m ON c.name = m.chat_name
        LEFT JOIN 
            User u ON c.creator = u.USERNAME
        LEFT JOIN (
            SELECT 
                chatID, 
                COUNT(*) AS total_likes
            FROM 
                Chat_Liked
            GROUP BY 
                chatID
        ) like_counts ON c.name = like_counts.chatID
        LEFT JOIN 
            Chat_Liked cl ON c.name = cl.chatID AND cl.Username = ?
        WHERE 
            c.principal = FALSE 
            AND c.region = ?
        GROUP BY 
            c.name, c.descri, u.PHOTO_URL, u.USERNAME, like_counts.total_likes, cl.liked;
    `
	rows, err := db.Query(queryChats, username, region)
	if err != nil {
		http.Error(w, "Server error while fetching chats", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type UserChat struct {
		Name         string
		MessageCount int
		Descri       string
		PhotoURL     string
		Creator      string
		TotalLikes   int
		UserLiked    bool
	}

	var chats []UserChat
	for rows.Next() {
		var chat UserChat
		if err := rows.Scan(&chat.Name, &chat.MessageCount, &chat.Descri, &chat.PhotoURL, &chat.Creator, &chat.TotalLikes, &chat.UserLiked); err != nil {
			log.Println("Error scanning chat data:", err)
			continue
		}
		chats = append(chats, chat)
	}

	// Final data struct
	data := struct {
		IsConnected bool
		Username    string
		Region      string
		MainChat    MainChat
		Chats       []UserChat
	}{
		IsConnected: username != "",
		Username:    username,
		Region:      region,
		MainChat:    mainChat,
		Chats:       chats,
	}

	if err := template.Must(template.ParseFiles("templates/welcome.html")).Execute(w, data); err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

// chiamato quando vuoi creare un chat, e salva il nome del chat con nome del creatore, nome del chat e in che regione si trova, ti ridirige poi verso /welcome
func CreateChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	creator, ok := session.Values["username"].(string)
	if !ok || creator == "" {
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	chatName := r.FormValue("chatname")
	chatDescription := r.FormValue("description") // Retrieve the description
	region := r.FormValue("region")
	if chatName == "" || region == "" {
		http.Error(w, "Chat name or region missing", http.StatusBadRequest)
		log.Println("Chat creation failed: missing chat name or region.")
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "CreerCompte", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	// Adjust the SQL to include the description field
	_, err = db.Exec("INSERT INTO chats (name, creator, region, descri, principal) VALUES (?, ?, ?, ?,?)", chatName, creator, region, chatDescription, 0)
	if err != nil {
		log.Printf("Chat creation failed: %v", err)
		http.Error(w, "Chat creation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Chat created successfully: %s in region %s by %s with description: %s", chatName, region, creator, chatDescription)
	http.Redirect(w, r, "/welcome", http.StatusSeeOther)
}

// chiamato quando scegli un chat, salva il nome del chat dove vuoi andare e ridirige verso /chat_messages
func SelectChatHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	chatName := r.URL.Query().Get("chatname") // Get chatname from query parameter
	if chatName == "" {
		http.Error(w, "Chat name missing", http.StatusBadRequest)
		log.Println("Chat selection failed: missing chat name in request.")
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	session.Values["chatname"] = chatName
	err = session.Save(r, w)
	if err != nil {
		log.Println("Error saving session:", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	log.Printf("Chatname stored in session: %s", chatName)
	w.WriteHeader(http.StatusOK)
}

// prende tutte le chat di una certa regione
func FetchChatsHandler(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("region")
	if region == "" {
		http.Error(w, "Region is required", http.StatusBadRequest)
		return
	}

	session, _ := Store.Get(r, "session-name")
	username, _ := session.Values["username"].(string)

	// Open the database
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "CreerCompte", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	// Fetch principal chat with total likes and user liked status
	queryMain := `
        SELECT 
            c.name AS chat_name, 
            COUNT(m.id) AS message_count, 
            c.descri, 
            r.REGION_IMG_URL, 
            COALESCE(like_counts.total_likes, 0) AS total_likes,
            COALESCE(cl.liked, FALSE) AS user_liked
        FROM 
            chats c
        LEFT JOIN 
            messages m ON c.name = m.chat_name
        LEFT JOIN 
            Region r ON c.region = r.REGION_NAME
        LEFT JOIN (
            SELECT 
                chatID, 
                COUNT(*) AS total_likes
            FROM 
                Chat_Liked
            GROUP BY 
                chatID
        ) like_counts ON c.name = like_counts.chatID
        LEFT JOIN 
            Chat_Liked cl ON c.name = cl.chatID AND cl.Username = ?
        WHERE 
            c.principal = TRUE 
            AND c.region = ?
        GROUP BY 
            c.name, c.descri, r.REGION_IMG_URL, like_counts.total_likes, cl.liked;
    `
	principal, err := db.Query(queryMain, username, region)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer principal.Close()

	type MainChat struct {
		Name         string
		MessageCount int
		Descri       string
		ImageURL     string
		TotalLikes   int
		UserLiked    bool
	}

	var mainChat MainChat
	if principal.Next() {
		err := principal.Scan(&mainChat.Name, &mainChat.MessageCount, &mainChat.Descri, &mainChat.ImageURL, &mainChat.TotalLikes, &mainChat.UserLiked)
		if err != nil {
			http.Error(w, "Failed to scan main chat data", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "No main chat found", http.StatusNotFound)
		return
	}

	// Fetch user chats with total likes and user liked status
	queryChats := `
        SELECT 
            c.name AS chat_name, 
            COUNT(m.id) AS message_count, 
            c.descri, 
            u.PHOTO_URL, 
            u.USERNAME, 
            COALESCE(like_counts.total_likes, 0) AS total_likes,
            COALESCE(cl.liked, FALSE) AS user_liked
        FROM 
            chats c
        LEFT JOIN 
            messages m ON c.name = m.chat_name
        LEFT JOIN 
            User u ON c.creator = u.USERNAME
        LEFT JOIN (
            SELECT 
                chatID, 
                COUNT(*) AS total_likes
            FROM 
                Chat_Liked
            GROUP BY 
                chatID
        ) like_counts ON c.name = like_counts.chatID
        LEFT JOIN 
            Chat_Liked cl ON c.name = cl.chatID AND cl.Username = ?
        WHERE 
            c.principal = FALSE 
            AND c.region = ?
        GROUP BY 
            c.name, c.descri, u.PHOTO_URL, u.USERNAME, like_counts.total_likes, cl.liked;
    `
	rows, err := db.Query(queryChats, username, region)
	if err != nil {
		http.Error(w, "Server error while fetching chats", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type UserChat struct {
		Name         string
		MessageCount int
		Descri       string
		PhotoURL     string
		Creator      string
		TotalLikes   int
		UserLiked    bool
	}

	var chats []UserChat
	for rows.Next() {
		var chat UserChat
		if err := rows.Scan(&chat.Name, &chat.MessageCount, &chat.Descri, &chat.PhotoURL, &chat.Creator, &chat.TotalLikes, &chat.UserLiked); err != nil {
			log.Println("Error scanning chat data:", err)
			continue
		}
		chats = append(chats, chat)
	}

	// Final data structure
	data := struct {
		IsConnected bool
		MainChat    MainChat
		Chats       []UserChat
	}{
		IsConnected: username != "",
		MainChat:    mainChat,
		Chats:       chats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Error encoding data", http.StatusInternalServerError)
	}
}

// ///////////////////////////////////////////// MESSAGES ///////////////////////////////////////////
// prende i messaggi dall db per darli alla pagina web
func FilMessagesHandler(w http.ResponseWriter, r *http.Request) {
	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	username, usernameExists := session.Values["username"].(string)
	chatName, chatNameExists := session.Values["chatname"].(string)
	if !usernameExists || username == "" || !chatNameExists || chatName == "" {
		// Redirect to /connection if the user is not logged in or chat is not selected
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Println("Error opening database:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT 
            m.id, 
            m.sender, 
            m.message, 
            strftime('%Y-%m-%d %H:%M:%S', m.timestamp) AS timestamp, 
            u.PHOTO_URL, 
            COALESCE(like_count, 0) AS number_of_likes,
            CASE WHEN ul.message_id IS NOT NULL THEN TRUE ELSE FALSE END AS user_liked
        FROM 
            messages m
        LEFT JOIN 
            User u ON m.sender = u.USERNAME
        LEFT JOIN (
            SELECT message_id, COUNT(*) AS like_count
            FROM Msg_Liked
            GROUP BY message_id
        ) likes ON m.id = likes.message_id
        LEFT JOIN 
            Msg_Liked ul ON m.id = ul.message_id AND ul.username = ?
        WHERE 
            m.chat_name = ?
        ORDER BY 
            m.timestamp ASC;`,
		username, chatName,
	)
	if err != nil {
		log.Println("Error fetching messages:", err)
		http.Error(w, "Error retrieving messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []struct {
		MessageID     int
		Sender        string
		Message       string
		TimeElapsed   string
		ImgUser       string
		NumberOfLikes int
		UserLiked     bool
	}

	for rows.Next() {
		var messageID int
		var sender, message, timestamp, imgUser string
		var numberOfLikes int
		var userLiked bool

		if err := rows.Scan(&messageID, &sender, &message, &timestamp, &imgUser, &numberOfLikes, &userLiked); err != nil {
			log.Println("Error scanning message row:", err)
			continue
		}

		// Calculate elapsed time
		elapsedTime, err := formatElapsedTime(timestamp)
		if err != nil {
			log.Println("Error parsing timestamp:", err)
			continue
		}

		messages = append(messages, struct {
			MessageID     int
			Sender        string
			Message       string
			TimeElapsed   string
			ImgUser       string
			NumberOfLikes int
			UserLiked     bool
		}{
			MessageID:     messageID,
			Sender:        sender,
			Message:       message,
			TimeElapsed:   elapsedTime,
			ImgUser:       imgUser,
			NumberOfLikes: numberOfLikes,
			UserLiked:     userLiked,
		})
	}

	data := struct {
		ChatName string
		Messages []struct {
			MessageID     int
			Sender        string
			Message       string
			TimeElapsed   string
			ImgUser       string
			NumberOfLikes int
			UserLiked     bool
		}
	}{
		ChatName: chatName,
		Messages: messages,
	}

	tmpl := template.Must(template.ParseFiles("templates/chat_messages.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

// una volta mandato, il messaggio viene salvato nella db
func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	chatName, ok := session.Values["chatname"].(string)
	if !ok || chatName == "" {
		http.Error(w, "Chat not selected. Please select a chat.", http.StatusBadRequest)
		log.Println("Chatname not found in session.")
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	message := r.FormValue("message")
	if message == "" {
		http.Error(w, "Message cannot be empty", http.StatusBadRequest)
		log.Println("Empty message received.")
		return
	}

	// Save current timestamp with full date and time
	currentTime := time.Now().Format("2006-01-02 15:04:05") // Full timestamp format

	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		renderError(w, "CreerCompte", "Erreur d'ouverture de la base de données.")
		return
	}
	defer db.Close()

	_, err = db.Exec(
		"INSERT INTO messages (chat_name, sender, message, timestamp) VALUES (?, ?, ?, ?)",
		chatName, username, message, currentTime,
	)
	if err != nil {
		http.Error(w, "Failed to save message", http.StatusInternalServerError)
		log.Println("Error saving message to database:", err)
		return
	}

	log.Printf("Message saved successfully: %s - %s: %s", chatName, username, message)
}

// prende tutti il messaggi di una chat specifica per poi fare apparirli nella pagina
func FetchMessagesHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session
	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	// Check if the user is logged in
	username, usernameExists := session.Values["username"].(string)
	chatName, chatNameExists := session.Values["chatname"].(string)
	if !usernameExists || username == "" || !chatNameExists || chatName == "" {
		// Redirect to /connection if the user is not logged in or chat is not selected
		http.Redirect(w, r, "/SeConnecter", http.StatusSeeOther)
		return
	}

	// Open the database
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Println("Error opening database:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Fetch messages for the specific chat
	rows, err := db.Query(
		`SELECT 
            m.id, 
            m.sender, 
            m.message, 
            strftime('%Y-%m-%d %H:%M:%S', m.timestamp) AS timestamp, 
            u.PHOTO_URL, 
            COALESCE(like_count, 0) AS number_of_likes,
            CASE WHEN ul.message_id IS NOT NULL THEN TRUE ELSE FALSE END AS user_liked
        FROM 
            messages m
        LEFT JOIN 
            User u ON m.sender = u.USERNAME
        LEFT JOIN (
            SELECT message_id, COUNT(*) AS like_count
            FROM Msg_Liked
            GROUP BY message_id
        ) likes ON m.id = likes.message_id
        LEFT JOIN 
            Msg_Liked ul ON m.id = ul.message_id AND ul.username = ?
        WHERE 
            m.chat_name = ?
        ORDER BY 
            m.timestamp ASC;`,
		username, chatName,
	)
	if err != nil {
		log.Println("Error fetching messages:", err)
		http.Error(w, "Server error while fetching messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []struct {
		MessageID     int    `json:"message_id"`
		Sender        string `json:"sender"`
		Message       string `json:"message"`
		TimeElapsed   string `json:"time_elapsed"`
		ImgUser       string `json:"img_user"`
		NumberOfLikes int    `json:"number_of_likes"`
		UserLiked     bool   `json:"user_liked"`
	}

	for rows.Next() {
		var messageID int
		var sender, message, timestamp, imgUser string
		var numberOfLikes int
		var userLiked bool

		if err := rows.Scan(&messageID, &sender, &message, &timestamp, &imgUser, &numberOfLikes, &userLiked); err != nil {
			log.Println("Error scanning message data:", err)
			continue
		}

		// Format elapsed time
		elapsedTime, err := formatElapsedTime(timestamp)
		if err != nil {
			log.Println("Error formatting timestamp:", err)
			continue
		}

		messages = append(messages, struct {
			MessageID     int    `json:"message_id"`
			Sender        string `json:"sender"`
			Message       string `json:"message"`
			TimeElapsed   string `json:"time_elapsed"`
			ImgUser       string `json:"img_user"`
			NumberOfLikes int    `json:"number_of_likes"`
			UserLiked     bool   `json:"user_liked"`
		}{
			MessageID:     messageID,
			Sender:        sender,
			Message:       message,
			TimeElapsed:   elapsedTime,
			ImgUser:       imgUser,
			NumberOfLikes: numberOfLikes,
			UserLiked:     userLiked,
		})
	}

	// Prepare JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func formatElapsedTime(input string) (string, error) {
	// Parse the input time string
	layout := "2006-01-02 15:04:05"
	inputTime, err := time.Parse(layout, input)
	if err != nil {
		return "", err
	}

	// Get the current time
	currentTime := time.Now()

	// Calculate the difference
	duration := currentTime.Sub(inputTime)

	// Handle specific cases
	years := int(duration.Hours() / (24 * 365))
	if years > 0 {
		return fmt.Sprintf("%d ans", years), nil
	}

	months := int(duration.Hours() / (24 * 30))
	if months > 0 {
		return fmt.Sprintf("%d mois", months), nil
	}

	days := int(duration.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%dj", days), nil
	}

	hours := int(duration.Hours())
	if hours > 0 {
		return fmt.Sprintf("%dh", hours), nil
	}
	timeStr := inputTime.Format("15:04")
	// Default case if none of the above applies
	return timeStr, nil
}

// //////////////////////////////////////// REGION HANDLER ///////////////////////////////////////////////
// salva il nome della region in cui si trova lo user
func RegionHandler(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("name")
	if region == "" {
		http.Error(w, "Region not selected. Please choose a region.", http.StatusBadRequest)
		log.Println("No region selected.")
		return
	}

	session, err := Store.Get(r, "session-name")
	if err != nil {
		log.Println("Error retrieving session:", err)
		http.Error(w, "Failed to retrieve session", http.StatusInternalServerError)
		return
	}

	session.Values["region"] = region
	err = session.Save(r, w)
	if err != nil {
		log.Println("Error saving session:", err)
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/welcome", http.StatusSeeOther)
}
