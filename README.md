# DaddyLive Kodi Repository

Dépôt Kodi pour l'addon DaddyLive (Live TV & Sports).

## Installation dans Kodi

### Méthode 1 — Via le dépôt (recommandé, mises à jour automatiques)

1. Dans Kodi : **Paramètres → Système → Modules complémentaires** → activer **Sources inconnues**
2. **Modules complémentaires → Installer depuis un fichier zip**
3. Ajoute la source : `https://guenole84.github.io/`
4. Installe `repository.daddylive-1.0.0.zip` depuis `repository.daddylive/`
5. **Installer depuis un dépôt → DaddyLive Repository → Extensions vidéo → Daddylive**

### Méthode 2 — Installation directe par zip

1. Télécharge `plugin.video.daddylive/plugin.video.daddylive-5.1.zip`
2. Dans Kodi : **Modules complémentaires → Installer depuis un fichier zip**

## Mise à jour

Pour mettre à jour l'addon après une modification :
1. Incrémenter `version` dans `plugin.video.daddylive/addon.xml`
2. Regénérer le zip et `addons.xml` avec le script `update_repo.py`
3. Committer et pousser sur GitHub
