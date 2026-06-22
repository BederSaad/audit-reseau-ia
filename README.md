🛡️ Audit Réseau Intelligent piloté par IA
📝 Description du Projet
Cette plateforme représente une solution de rupture dans le domaine de l'automatisation de l'audit de sécurité et de la gestion des vulnérabilités. Conçue spécifiquement pour répondre aux exigences de résilience des infrastructures critiques (notamment le secteur bancaire), l'application orchestre intelligemment des moteurs de scan de référence, normalise la télémétrie brute en temps réel, évalue les surfaces d'attaque et intègre un Agent IA conversationnel dédié à la Threat Intelligence et à l'aide à la remédiation.

⚙️ Architecture Globale du Pipeline (Cinématique de Scan)
L'application suit un flux d'exécution asynchrone et modulaire hautement optimisé :

```plaintext
[ Requête Target ] ➔ [ Moteur Nmap Asynchrone ] ➔ [ Parseur XML natif ]
                                                          │
   ┌──────────────────────────────────────────────────────┘
   ▼
[ Isolation des Services Web (80, 443, 8080) ] ➔ [ Moteur Cyber Nuclei ]
                                                          │
   ┌──────────────────────────────────────────────────────┘
   ▼
[ Normalisation JSON-lines ] ➔ [ Ingestion Relationnelle PostgreSQL (SQLAlchemy) ]
```

🚀 Fonctionnalités Clés & Objectifs
Cartographie Réseau Non-Bloquante : Scan d'infrastructure approfondi, identification des ports ouverts, détection de versions et fingerprinting des OS via un wrapper Nmap optimisé pour éviter les blocages de boucles d'événements (Event Loop).

Scan Applicatif Automatisé : Détection ciblée des vulnérabilités web et des failles logicielles critiques (OWASP Top 10) via l'intégration dynamique du moteur de templates Nuclei.

Persistance Institutionnelle : Modélisation relationnelle rigoureuse sous PostgreSQL pour archiver l'historique des audits, le tracking des hôtes, l'évolution des services (CPE) et le registre des vulnérabilités.

Corrélation Cyber & Scoring : Association automatique des services détectés aux bases de connaissances CVE et calcul du score de criticité pour hiérarchiser les urgences.

Assistant IA Cyber : Agent conversationnel intelligent exploitant le RAG (Retrieval-Augmented Generation) pour analyser les rapports de scan et générer des playbooks de remédiation sur mesure.

🛠️ Stack Technique
Sécurité & Télémétrie : Nmap (Analyse réseau), Nuclei (Analyse de vulnérabilités applicatives).

Backend : FastAPI (Python), Uvicorn, Pydantic (Validation stricte des inputs), asyncio (Gestion des threads workers).

Base de Données & ORM : PostgreSQL, SQLAlchemy (Couche d'abstraction relationnelle).

Frontend : React.js, Tailwind CSS (Composants interactifs, esthétique minimaliste et moderne type Glassmorphism).

Déploiement : Docker, Docker Compose pour une isolation totale des briques applicatives.

📁 Structure du Répertoire
```plaintext
audit-reseau-ia/
├── backend/                  # Moteur d'API et orchestration de sécurité
│   ├── database.py           # Configuration de la session PostgreSQL et de l'engine
│   ├── models.py             # Schémas relationnels SQLAlchemy (Scans, Hosts, Services, Vulns)
│   ├── main.py               # Endpoints de l'API et logique des wrappers de scan
│   └── requirements.txt      # Dépendances Python du projet
├── frontend/                 # Interface utilisateur de la plateforme
│   ├── src/                  # Composants React et layout du Dashboard
│   └── package.json          # Dépendances et scripts Node.js
├── docs/                     # Documentation de conception et journal de bord technique
└── tests/                    # Validations unitaires et tests d'intégration des pipelines
```

🗺️ Feuille de Route & Statut d'Avancement
| Phase | Objectif Fonctionnel | Statut |
|---|---|---|
| Phase 1 | Initialisation Frontend React & Design System (Fintech/Glassmorphism) | Complété |
| Phase 1 | Configuration FastAPI & Wrapper d'exécution Nmap (Correction Bug Windows) | Complété |
| Phase 1 | Intégration du Moteur Nuclei & Persistance Base de Données PostgreSQL | 🔄 En Cours |
| Phase 2 | Implémentation du Moteur de Corrélation CVE & Scoring de Risque CVSS | ⏳ En Attente |
| Phase 3 | Déploiement de l'Agent IA Conversationnel & Intégration RAG Cyber | ⏳ En Attente |
| Phase 4 | Conteneurisation Multi-services Docker & Préparation de la Soutenance | ⏳ En Attente |

⚡ Guide de Démarrage Rapide
1. Prérequis Système
Avant de démarrer l'application, assurez-vous que les outils suivants sont installés et configurés dans les variables d'environnement de votre système (PATH) :

*   Nmap (Accessible via la commande nmap)
*   Nuclei (Accessible via la commande nuclei)
*   PostgreSQL (Service actif sur le port 5432)

2. Configuration de la Base de Données
Connectez-vous à votre instance PostgreSQL et initialisez une base de données vide dédiée au projet :

```sql
CREATE DATABASE audit_db;
```

3. Lancement du Serveur Backend (FastAPI)
Ouvrez un terminal avec des privilèges administratifs ("Exécuter en tant qu'administrateur") et exécutez :

```bash
# Accéder au dossier du backend
cd backend

# Installer l'ensemble des modules requis
pip install -r requirements.txt

# Initialiser et exécuter le serveur Uvicorn
python -m uvicorn main:app --reload
```
💡 La documentation interactive complète du projet et l'interface de test des routes sont disponibles en temps réel à l'adresse : http://127.0.0.1:8000/docs

4. Lancement du Tableau de Bord Frontend (React)
Dans un second terminal dissocié :

```bash
# Accéder au dossier du frontend
cd frontend

# Installer les modules Node requis
npm install

# Démarrer le serveur de développement local
npm start
```
L'interface utilisateur s'ouvrira automatiquement à l'adresse http://localhost:3000.

👥 Équipe et Cadre de Réalisation
Développeur & Concepteur : Beder Saad

Type de Projet : Projet d'Innovation / Stage de Fin d'Études

Focus Sectoriel : Sécurisation et résilience des infrastructures bancaires et d'entreprise.
