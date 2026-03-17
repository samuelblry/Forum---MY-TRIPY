# MyTripy ✈️🇫🇷

Un forum collaboratif dédié à l'exploration et au partage d'expériences sur les magnifiques régions et départements de France. MyTripy permet aux utilisateurs de se connecter, d'échanger des conseils et de découvrir la culture, la géographie et le charme des destinations françaises.

---

## 👥 Projet de groupe

**MyTripy** a été conçu et développé dans le cadre d'un **projet de groupe collaboratif**. L'objectif était de créer une application web complète, de la base de données au front-end, en passant par le back-end, tout en gérant le travail en équipe.

### 👨‍💻 L'équipe (Auteurs)
* **Sara SMITH** 
* **Mathias BOUCHENOIRE** 
* **Samuel BOUHNIK-LOURY** 
* **William PONS**

---

## 📝 Description 

MyTripy est une plateforme web conçue pour inspirer les passionnés de voyage à partager leurs expériences sur les régions et départements français. Développée avec **Go (Golang)**, **HTML**, **CSS** et une base de données **SQLite**, MyTripy est une application intuitive et interactive. 

Grâce à l’intégration de **Docker**, l’accès à notre site est simplifié quel que soit le système d’exploitation utilisé. Que vous soyez un voyageur expérimenté ou un explorateur novice, MyTripy vous propose une communauté conviviale dédiée au partage et à la découverte.

---

## 🚀 Prise en main

### 🛠️ Dépendances 

Avant de configurer MyTripy, assurez-vous d'avoir les éléments suivants installés sur votre machine :
* **Go** (version 1.24.1 ou supérieure)
* **Docker** (version 28.0.1 ou supérieure)
* **SQLite** (version 3.38.2 ou supérieure)
* Un navigateur web (Chrome, Firefox, Safari, etc.)

### 📥 Installation et exécution

1. **Clonez ce dépôt :**
   ```bash
   git clone https://github.com/UDR0/forum.git
   cd forum
   ```

2. **Démarrage avec Docker (Recommandé) :**
   - Construction de l'image :
     ```bash
     docker build -t forum .
     ```
   - Lancement du conteneur :
     ```bash
     docker run -v ${PWD}/forum.db:/app/forum.db -p 8080:8080 forum
     ```

3. **Démarrage en local avec Go :**
   ```bash
   go run main.go
   ```

Une fois le serveur démarré, le site sera accessible à l'adresse suivante : **[http://localhost:8080](http://localhost:8080)**

---

## 🆘 Aide et Dépannage

Si vous rencontrez des problèmes lors de l'installation ou de l'exécution de MyTripy, voici quelques étapes de dépannage :

1. **Vérifiez la base de données** : 
   - Assurez-vous que le fichier `forum.db` est présent à la racine du projet, qu'il n'est pas vide (0 octet) et qu'il contient les bonnes données (attention aux conflits de fusion Git).

2. **Conflits de port** : 
   - Si le port **8080** est déjà utilisé sur votre machine, modifiez-le lors de l'exécution de l'image Docker :
     ```bash
     docker run -v ${PWD}/forum.db:/app/forum.db -p <nouveau_port>:8080 forum
     ```

3. **Problèmes avec Docker** :
   - Vérifiez que Docker est correctement installé et en cours d'exécution :
     ```bash
     docker --version
     docker ps
     ```
