# Import JSON dans Notepad++++

## Avec un script qui copie le JSON

Le script Tampermonkey peut continuer à copier son tableau JSON dans le presse-papiers. Dans la page extension du bloc-notes, **Ctrl + Alt + X** importe les champs dans Summary, sans modifier le presse-papiers, les notes ou les données déjà collectées.

Le JSON peut aussi être collé dans **Logs** ou ouvert depuis un fichier `.json` avec **Open**, en version autonome comme en version extension. Un fichier JSON ajoute les champs sans remplacer les Logs en cours. **Add to summary** archive le JSON présent dans Logs et libère la saisie.

```json
[
  {"user.name": "alice", "host.hostname": "PC-01"},
  {"user.name": "bob", "host.hostname": "PC-02"},
  {"host.hostname": "PC-02"}
]
```

Cet exemple ajoute `user.name`, `host.hostname`, `user.name2` et `host.hostname2`. Le second `PC-02` n’est pas ajouté à nouveau. Les identifiants internes restent uniques ; les suffixes évitent aussi les noms numérotés déjà présents.

- Les clés avec des points restent des noms de champs. Aucun objet imbriqué n’est créé à partir de ces points.
- Comme dans la collecte existante, une valeur identique peut partager une ligne avec plusieurs clés. Les valeurs différentes restent indépendantes.
- Les chaînes gardent leurs espaces internes et leurs retours à la ligne. Les emojis et pictogrammes, ainsi que les espaces et lignes vides en début et fin de valeur, sont retirés. `Not mitigated` devient `Unmitigated`. Les valeurs multilignes disposent d’une zone éditable dans Summary.
- `0` et `false` sont conservés. Les valeurs nulles, les chaînes vides et les collections vides sont ignorées.
- Un tableau de valeurs associé à une clé ajoute ses valeurs distinctes séparément. Les objets présents dans un tableau développent leurs propres champs, sans préfixe du conteneur : `members: [{"name":"Molecule Man"},{"name":"Madame Uppercut"}]` donne `name` et `name2`. Un objet associé directement à une clé reste du JSON textuel.
- Supprimer une valeur de Summary permet de la réimporter. Un nouveau collage JSON constitue un nouvel import, même si son contenu est identique au précédent. Les valeurs encore présentes restent dédoublonnées ; les clés ignorées et les exclusions liées aux modifications restent prises en compte.
- Les champs connus comme `user.name`, `host.hostname`, `source.ip`, `destination.ip`, `file.path` et `process.name` alimentent les variables de remédiation existantes. Aucune remédiation ni tactique n’est sélectionnée automatiquement.

## Pays, fichiers et VirusTotal

Ces règles s’appliquent à tous les imports JSON : collage dans Logs, fichier `.json`, **Ctrl + Alt + X**, `importJSON`, envoi Tampermonkey par l’extension et glisser-déposer.

**Pays.** Un champ pays est rattaché à l’adresse IP ou à l’URL du même objet et du même contexte :

| Champ pays | Entité recevant le pays |
| --- | --- |
| `source.geo.country_iso_code`, `source.geo.country_name` | `source.ip` (ou `source.address` si c’est une IP) |
| `destination.geo.…`, `client.geo.…`, `server.geo.…`, `host.geo.…` | `destination.ip`, `client.ip`, `server.ip`, `host.ip` |
| `url.geo.…` | `url.full`, `url.original` |
| `geo.country_iso_code`, `geo.country_name`, `geoip.country_code2` (sans préfixe) | l’unique IP de l’objet ; à défaut d’IP, son unique URL |

Les variantes `country_code` et `country`, ainsi que les séparateurs `_`, sont aussi reconnues (`src_ip` avec `src_country`). Le code ISO est prioritaire sur le nom ; un nom courant français ou anglais est converti en code. Le champ rattaché n’est pas ajouté comme paire séparée : il apparaît dans le champ **Country** de l’IP ou de l’URL, avec son drapeau.

Aucun rattachement n’est fait au hasard. Le champ pays reste une paire ordinaire si le contexte ne désigne pas une seule entité : plusieurs IP pour un pays sans préfixe, tableau de plusieurs adresses, codes contradictoires, préfixe sans IP ni URL correspondante. Un pays déjà renseigné n’est jamais remplacé par un import ; il reste modifiable et supprimable à la main. Aucun pays n’est déduit de l’adresse ou de l’extension du domaine.

**Fichiers.** Dans un même objet, `file.name`, `file.path` et `file.hash.sha256` / `sha1` / `md5` forment un seul fichier : le nom reste la valeur de la paire, le chemin et le hash le plus fort (SHA256, puis SHA1, puis MD5) deviennent ses détails **Path** et **Hash**. Les formes à plat `filename`, `filepath`, `sha256`, `sha1`, `md5` et `hash` sont reconnues de la même façon, ainsi que les préfixes (`email.attachments.file.name`). Sans nom, le hash est rattaché au chemin. Les autres hash restent des paires, chacune avec son lien VirusTotal. Deux fichiers de même nom et de hash différents ne sont pas fusionnés. `{FILE}` et `{HASH}` des remédiations lisent aussi ces détails.

**VirusTotal.** Les liens sont construits localement à partir des valeurs importées. Aucun appel à VirusTotal, aucune réputation récupérée, aucun fichier ni indicateur envoyé par l’import.

```json
{
  "source.ip": "98.56.54.185",
  "source.geo.country_iso_code": "NL",
  "file.name": "mail.txt",
  "file.path": "C:\\Users\\j.dupont\\Downloads\\mail.txt",
  "file.hash.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

Cet exemple ajoute deux paires, `source.ip` (Country `NL 🇳🇱`) et `file.name` (Path et Hash SHA256), chacune avec son lien VirusTotal dans le rapport.

Un champ `event.url` (ou `event.reference`, `alert.url`, `rule.reference`) contenant une adresse http(s) est un lien vers la console d’origine : il est cliquable dans le rapport, sans lien VirusTotal. Les autres URL ne sont jamais cliquables vers leur destination.

## Fonction centralisée

Dans la page du bloc-notes :

```js
const result = importJSON(data);
// Aussi disponible sous SOCNote.importJSON(data).
```

`data` accepte un objet, un tableau d’objets ou leur texte JSON. Le résultat contient `ok`, et `error` en cas d’échec. `jsonCount` compte les nouveaux champs/valeurs ; `count` compte les nouveaux envois enregistrés. Pour un envoi identifié :

```js
const result = SOCNote.importJSON(data, { requestId: "siem-alert-1234-export-1" });
```

Réutiliser cet identifiant avec les mêmes données ne les réimporte pas, même après rechargement du brouillon. Le réutiliser avec des données différentes produit une erreur. Utilisez un nouvel identifiant pour un nouvel export. Les identifiants acceptent 1 à 100 lettres, chiffres, points, tirets, deux-points ou underscores.

L’interface, les captures de sélection/presse-papiers et le connecteur utilisent le même moteur dans `js/json-import.js`. Un import valide est sauvegardé avant confirmation. Une erreur de validation ou de sauvegarde laisse les champs déjà présents intacts.

## Envoi direct depuis Tampermonkey

### Script Tampermonkey fourni

1. Dans `manifest.json`, remplacez `CHANGEME` dans `https://CHANGEME/*` par l’adresse de votre SIEM (par exemple `https://siem.example.invalid/alerts/*`). Rechargez l’extension (version 1.4.0) et acceptez l’accès à ce site si Chrome le demande.
2. Installez le script de `tampermonkey/` dans Tampermonkey, puis collez votre logo Base64 dans `LOGO`.
3. Gardez l’onglet Notepad++++ de l’extension ouvert.

Un clic sur le bouton du script copie le tableau en JSON et l’envoie directement à Notepad++++. Aucune activation de l’extension n’est nécessaire sur les pages déclarées dans `manifest.json` : le récepteur y démarre automatiquement. Tant que `CHANGEME` n’est pas remplacé, cliquez sur l’icône de l’extension sur la page avant d’utiliser le bouton. Chaque clic est un nouvel envoi : une valeur supprimée dans Summary revient au clic suivant, les valeurs encore présentes ne sont pas dupliquées. Un message en bas à droite confirme la copie, l’envoi puis l’import. Si l’envoi échoue, la copie reste disponible : collez le JSON dans Logs ou utilisez **Ctrl + Alt + X**.

### Autre script

Sur une autre page, cliquez une fois sur l’icône **Notepad++++ SOC Capture** (ou Ctrl + Shift + X) pour activer le récepteur ; renouvelez l’activation après navigation ou rechargement. Votre script envoie ensuite son JSON avec le protocole décrit plus bas ; le script de `tampermonkey/` en est un exemple complet (envoi, attente de l’import et messages).

Le SIEM et le bloc-notes peuvent être ouverts dans deux fenêtres différentes du **même profil Chrome/Edge**. L’onglet du bloc-notes doit rester ouvert pour importer automatiquement en arrière-plan ; il ne prend pas le focus du SIEM. S’il est fermé, l’envoi reste dans la file locale jusqu’à son ouverture.

Le bloc-notes confirme le nombre de champs importés. Un échec de sauvegarde est signalé à l’expéditeur et reste en attente pour être réessayé ; renvoyer le même identifiant avec les mêmes données ne crée pas de doublon.

## Protocole personnalisé

Votre script émet :

```js
window.postMessage({
  channel: "soc-note-json/v1",
  type: "send",
  requestId: "identifiant-unique-de-cet-envoi",
  data: tableauJSON
}, location.origin);
```

La réponse sur la même fenêtre utilise `type: "result"`, le même `requestId`, `ok` et `status: "queued"` ou `"imported"`. Pour connaître le statut ultérieur, envoyez `type: "status"` avec le même identifiant. `error` peut préciser un échec de sauvegarde en attente.

Le récepteur contrôle la fenêtre et l’origine du message. Le worker contrôle l’identité de l’extension, l’onglet source et le cadre principal. Les réponses ne contiennent aucune note ni donnée d’un autre onglet. Tous les scripts de la page SIEM activée peuvent utiliser ce récepteur ; l’activation n’authentifie pas un script Tampermonkey particulier.

L’activation ciblée utilise les permissions existantes `activeTab` et `scripting`, sans accès permanent à tous les sites. Voir les documentations Chrome sur les [scripts de contenu](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts) et les [messages d’extension](https://developer.chrome.com/docs/extensions/develop/concepts/messaging).

## Limites et conservation

Un envoi est limité à 500 000 caractères et 200 paires champ/valeur distinctes, avec des clés de 256 caractères maximum. Les limites de l’investigation et de la sauvegarde existantes restent applicables ; aucune troncature silencieuse n’est effectuée.

La file et jusqu’à 5 000 reçus d’envoi sont conservés dans `chrome.storage.session`. Une suspension du worker conserve ces données ; un redémarrage du navigateur ou un rechargement de l’extension efface les envois encore en attente. Les envois importés et leurs identifiants sont conservés avec Current Analysis. **New** ouvre une nouvelle investigation ; **Undo** fonctionne comme pour les autres imports.

L’envoi direct vise la page **extension** du bloc-notes. Une page autonome `file://` accepte les imports manuels, mais ne reçoit pas la file de l’extension. Aucun service tiers, aucune requête réseau et aucun accès au presse-papiers ne sont utilisés par l’envoi direct.
