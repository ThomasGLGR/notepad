"use strict";
window.SOCNote.remediationData = (() => {
  // Configuration only: UI and engine do not depend on the tactic count or labels.
  const definitions = [
    ["reconnaissance", "Reconnaissance", "TA0043", [
      "Identify the source of the reconnaissance activity.",
      "Block the IP addresses identified as malicious.",
      "Review the public exposure of the targeted services.",
      "Limit publicly accessible information about the infrastructure.",
      "Monitor new activity from the same sources."
    ]],
    ["resource-development", "Resource Development", "TA0042", [
      "Block the domains identified as malicious.",
      "Block IP addresses associated with the malicious infrastructure.",
      "Add the identified indicators to detection rules.",
      "Monitor new related domains or infrastructure.",
      "Check whether the infrastructure was used in previous incidents."
    ]],
    ["initial-access", "Initial Access", "TA0001", [
      "Block the IP address {IP}.", "Block the domain {DOMAIN}.", "Block the URL {URL}.",
      "Remove or quarantine the file {FILE}.", "Block the hash {HASH}.",
      "Reset the password for the account {USER}.", "Revoke active sessions for the account {USER}.",
      "Review MFA methods for the account {USER}.", "Check whether other users were targeted.",
      "Look for similar events on other hosts."
    ]],
    ["execution", "Execution", "TA0002", [
      "Stop the process {PROCESS}.", "Isolate the host {HOST}.",
      "Remove or quarantine the file {FILE}.", "Block the hash {HASH}.",
      "Look for the same process on other hosts.", "Review the related parent and child processes.",
      "Review the command line used for execution.", "Check whether the activity is a legitimate administrative action."
    ]],
    ["persistence", "Persistence", "TA0003", [
      "Remove the identified persistence mechanism.", "Isolate the host {HOST}.",
      "Review suspicious scheduled tasks.", "Review newly created or modified services.",
      "Review registry keys used for persistence.", "Review automatic startup entries.",
      "Remove unauthorized accounts.", "Reset potentially compromised credentials.",
      "Look for the same persistence mechanism on other hosts."
    ]],
    ["privilege-escalation", "Privilege Escalation", "TA0004", [
      "Revoke unauthorized privileges.", "Reset the password for the account {USER}.",
      "Revoke active sessions for the account {USER}.", "Review the account's privileged group memberships.",
      "Review recent changes to access rights and privileges.", "Isolate the host {HOST} if compromise is suspected.",
      "Look for the same activity on other privileged accounts.", "Review recently created or modified administrator accounts."
    ]],
    ["defense-evasion", "Defense Evasion", "TA0005", [
      "Isolate the host {HOST}.", "Restore disabled security controls.",
      "Check the status of endpoint detection and antivirus protection.", "Review recently added antivirus exclusions.",
      "Review deleted or altered logs.", "Look for similar defense evasion activity on other hosts.",
      "Block tools identified as malicious.", "Review changes to security policies."
    ]],
    ["credential-access", "Credential Access", "TA0006", [
      "Reset the password for the account {USER}.", "Revoke active sessions for the account {USER}.",
      "Review registered MFA methods.", "Revoke existing authentication tokens.",
      "Review recent account sign-ins.", "Review accounts with elevated privileges.",
      "Look for unusual use of credentials.", "Check whether other accounts were exposed.",
      "Isolate the host {HOST} if credentials may have been extracted from it."
    ]],
    ["discovery", "Discovery", "TA0007", [
      "Review the discovery commands that were executed.", "Identify the account that initiated the activity.",
      "Check whether the activity is a legitimate administrative operation.", "Look for similar commands on other hosts.",
      "Isolate the host {HOST} if the activity is linked to a compromise.", "Review access after the discovery activity.",
      "Review resources accessible to the account {USER}."
    ]],
    ["lateral-movement", "Lateral Movement", "TA0008", [
      "Isolate the source host {HOST}.", "Block the related network communications.",
      "Reset credentials used for lateral movement.", "Revoke active sessions for the account {USER}.",
      "Identify the hosts accessed by the account.", "Review account activity on other hosts.",
      "Look for the same activity across the environment.", "Temporarily restrict network access for the compromised account.",
      "Review the use of RDP, SMB, WinRM or SSH."
    ]],
    ["collection", "Collection", "TA0009", [
      "Identify potentially collected data.", "Review access to the affected files and directories.",
      "Isolate the host {HOST} if needed.", "Review suspicious archives or temporary files.",
      "Remove malicious data collection files.", "Look for the same activity on other systems.",
      "Review access rights for the account {USER}.", "Check whether the collected data was transferred."
    ]],
    ["command-and-control", "Command and Control", "TA0011", [
      "Block the IP address {IP}.", "Block the domain {DOMAIN}.", "Block the URL {URL}.", "Isolate the host {HOST}.",
      "Block the hash {HASH}.", "Look for connections to the same indicator on other hosts.",
      "Add the identified indicators to detection rules.", "Review recurring or periodic network connections.",
      "Check whether other hosts contact the same infrastructure.",
      "Remove files or processes associated with the command and control channel."
    ]],
    ["exfiltration", "Exfiltration", "TA0010", [
      "Block the destination {DST_IP}.", "Block the domain {DOMAIN}.", "Isolate the host {HOST}.",
      "Identify potentially exfiltrated data.", "Review the volume of transferred data.", "Identify the accounts involved.",
      "Revoke active sessions for the account {USER}.", "Look for similar transfers from other hosts.",
      "Preserve evidence needed for the investigation.", "Follow the incident management procedure."
    ]],
    ["impact", "Impact", "TA0040", [
      "Isolate the host {HOST}.", "Disable the account {USER} if needed.", "Revoke active sessions.",
      "Identify affected systems and data.", "Restore files from a clean backup if needed.",
      "Verify backup integrity.", "Disable the mechanisms causing the impact.",
      "Look for the same activity on other systems.", "Preserve evidence needed for the investigation.",
      "Follow the appropriate incident response procedure."
    ]]
  ];
  const catalog = definitions.map(([id, name, mitreId, phrases]) => ({
    id, name, mitreId, origin: "default",
    remediations: phrases.map((template, index) => ({
      id: id + "-" + (index + 1), origin: "default", template, generic: "", enabled: true, favorite: false
    }))
  }));
  const legacyTemplates = {"reconnaissance-1": "Identifier l'origine de l'activité de reconnaissance.", "reconnaissance-2": "Bloquer les adresses IP identifiées comme malveillantes.", "reconnaissance-3": "Vérifier l'exposition publique des services ciblés.", "reconnaissance-4": "Limiter les informations publiquement accessibles concernant l'infrastructure.", "reconnaissance-5": "Surveiller toute nouvelle activité provenant des mêmes sources.", "resource-development-1": "Bloquer les domaines identifiés comme malveillants.", "resource-development-2": "Bloquer les adresses IP associées à l'infrastructure malveillante.", "resource-development-3": "Ajouter les indicateurs identifiés aux mécanismes de détection.", "resource-development-4": "Surveiller l'apparition de nouveaux domaines ou infrastructures associés.", "resource-development-5": "Vérifier si l'infrastructure identifiée a déjà été utilisée dans d'autres incidents.", "initial-access-1": "Bloquer l'adresse IP {IP}.", "initial-access-2": "Bloquer le domaine {DOMAIN}.", "initial-access-3": "Bloquer l'URL {URL}.", "initial-access-4": "Supprimer ou mettre en quarantaine le fichier {FILE}.", "initial-access-5": "Bloquer le hash {HASH}.", "initial-access-6": "Réinitialiser le mot de passe du compte {USER}.", "initial-access-7": "Révoquer les sessions actives du compte {USER}.", "initial-access-8": "Vérifier les méthodes MFA associées au compte {USER}.", "initial-access-9": "Vérifier si d'autres utilisateurs ont été ciblés.", "initial-access-10": "Rechercher des événements similaires sur d'autres machines.", "execution-1": "Arrêter le processus {PROCESS}.", "execution-2": "Isoler la machine {HOST}.", "execution-3": "Supprimer ou mettre en quarantaine le fichier {FILE}.", "execution-4": "Bloquer le hash {HASH}.", "execution-5": "Rechercher l'exécution du même processus sur d'autres machines.", "execution-6": "Vérifier les processus parents et enfants associés.", "execution-7": "Examiner la ligne de commande associée à l'exécution.", "execution-8": "Vérifier si l'activité correspond à une action administrative légitime.", "persistence-1": "Supprimer le mécanisme de persistance identifié.", "persistence-2": "Isoler la machine {HOST}.", "persistence-3": "Vérifier les tâches planifiées suspectes.", "persistence-4": "Vérifier les services nouvellement créés ou modifiés.", "persistence-5": "Vérifier les clés de registre utilisées pour la persistance.", "persistence-6": "Vérifier les éléments de démarrage automatique.", "persistence-7": "Supprimer les comptes non autorisés.", "persistence-8": "Réinitialiser les identifiants potentiellement compromis.", "persistence-9": "Rechercher le même mécanisme de persistance sur d'autres machines.", "privilege-escalation-1": "Révoquer les privilèges non autorisés.", "privilege-escalation-2": "Réinitialiser le mot de passe du compte {USER}.", "privilege-escalation-3": "Révoquer les sessions actives du compte {USER}.", "privilege-escalation-4": "Vérifier les groupes privilégiés auxquels appartient le compte.", "privilege-escalation-5": "Vérifier les modifications récentes des droits et privilèges.", "privilege-escalation-6": "Isoler la machine {HOST} si une compromission est suspectée.", "privilege-escalation-7": "Rechercher la même activité sur d'autres comptes privilégiés.", "privilege-escalation-8": "Examiner les comptes administrateurs récemment créés ou modifiés.", "defense-evasion-1": "Isoler la machine {HOST}.", "defense-evasion-2": "Restaurer les mécanismes de sécurité désactivés.", "defense-evasion-3": "Vérifier l'état de l'EDR ou de l'antivirus.", "defense-evasion-4": "Rechercher les exclusions antivirus récemment ajoutées.", "defense-evasion-5": "Examiner les journaux supprimés ou altérés.", "defense-evasion-6": "Rechercher des mécanismes similaires d'évasion sur d'autres machines.", "defense-evasion-7": "Bloquer les outils identifiés comme malveillants.", "defense-evasion-8": "Vérifier les modifications apportées aux politiques de sécurité.", "credential-access-1": "Réinitialiser le mot de passe du compte {USER}.", "credential-access-2": "Révoquer les sessions actives du compte {USER}.", "credential-access-3": "Vérifier les méthodes MFA enregistrées.", "credential-access-4": "Révoquer les tokens d'authentification existants.", "credential-access-5": "Vérifier les authentifications récentes du compte.", "credential-access-6": "Vérifier les comptes disposant de privilèges élevés.", "credential-access-7": "Rechercher une utilisation anormale des identifiants.", "credential-access-8": "Vérifier si d'autres comptes ont été exposés.", "credential-access-9": "Isoler la machine {HOST} si les identifiants ont pu être extraits depuis celle-ci.", "discovery-1": "Vérifier les commandes de découverte exécutées.", "discovery-2": "Identifier le compte ayant initié l'activité.", "discovery-3": "Vérifier si l'activité correspond à une opération administrative légitime.", "discovery-4": "Rechercher des commandes similaires sur d'autres machines.", "discovery-5": "Isoler la machine {HOST} si l'activité est associée à une compromission.", "discovery-6": "Vérifier les accès réalisés après la phase de découverte.", "discovery-7": "Examiner les ressources auxquelles le compte {USER} avait accès.", "lateral-movement-1": "Isoler la machine source {HOST}.", "lateral-movement-2": "Bloquer les communications réseau associées.", "lateral-movement-3": "Réinitialiser les identifiants utilisés pour le déplacement latéral.", "lateral-movement-4": "Révoquer les sessions actives du compte {USER}.", "lateral-movement-5": "Identifier les machines auxquelles le compte a accédé.", "lateral-movement-6": "Vérifier l'activité du compte sur les autres machines.", "lateral-movement-7": "Rechercher la même activité sur l'ensemble du périmètre.", "lateral-movement-8": "Restreindre temporairement les accès réseau du compte compromis.", "lateral-movement-9": "Vérifier l'utilisation de protocoles tels que RDP, SMB, WinRM ou SSH.", "collection-1": "Identifier les données potentiellement collectées.", "collection-2": "Vérifier les accès aux fichiers et répertoires concernés.", "collection-3": "Isoler la machine {HOST} si nécessaire.", "collection-4": "Vérifier la création d'archives ou de fichiers temporaires suspects.", "collection-5": "Supprimer les fichiers de collecte malveillants.", "collection-6": "Rechercher la même activité sur d'autres systèmes.", "collection-7": "Examiner les droits d'accès du compte {USER}.", "collection-8": "Vérifier si les données collectées ont été transférées.", "command-and-control-1": "Bloquer l'adresse IP {IP}.", "command-and-control-2": "Bloquer le domaine {DOMAIN}.", "command-and-control-3": "Bloquer l'URL {URL}.", "command-and-control-4": "Isoler la machine {HOST}.", "command-and-control-5": "Bloquer le hash {HASH}.", "command-and-control-6": "Rechercher les communications vers le même IOC sur d'autres machines.", "command-and-control-7": "Ajouter les IOC identifiés aux mécanismes de détection.", "command-and-control-8": "Examiner les connexions réseau récurrentes ou périodiques.", "command-and-control-9": "Vérifier si d'autres machines communiquent avec la même infrastructure.", "command-and-control-10": "Supprimer les fichiers ou processus associés au canal de commande et contrôle.", "exfiltration-1": "Bloquer la destination {DST_IP}.", "exfiltration-2": "Bloquer le domaine {DOMAIN}.", "exfiltration-3": "Isoler la machine {HOST}.", "exfiltration-4": "Identifier les données potentiellement exfiltrées.", "exfiltration-5": "Vérifier le volume de données transféré.", "exfiltration-6": "Identifier les comptes impliqués.", "exfiltration-7": "Révoquer les sessions actives du compte {USER}.", "exfiltration-8": "Vérifier les transferts similaires depuis d'autres machines.", "exfiltration-9": "Préserver les éléments nécessaires à l'investigation.", "exfiltration-10": "Escalader l'incident conformément à la procédure de gestion des incidents.", "impact-1": "Isoler la machine {HOST}.", "impact-2": "Bloquer le compte {USER} si nécessaire.", "impact-3": "Révoquer les sessions actives.", "impact-4": "Identifier les systèmes et données affectés.", "impact-5": "Restaurer les fichiers depuis une sauvegarde saine si nécessaire.", "impact-6": "Vérifier l'intégrité des sauvegardes.", "impact-7": "Désactiver les mécanismes responsables de l'impact.", "impact-8": "Rechercher la même activité sur d'autres systèmes.", "impact-9": "Préserver les preuves nécessaires à l'investigation.", "impact-10": "Appliquer la procédure de réponse à incident appropriée."};
  const defaultItems = new Map(catalog.flatMap(tactic => tactic.remediations.map(item => [item.id, item])));
  function upgradeTemplate(item) {
    const current = defaultItems.get(item.id);
    if (current && item.template === legacyTemplates[item.id]) item.template = current.template;
    return item;
  }
  function upgradeCatalog(tactics) {
    for (const tactic of tactics) for (const item of tactic.remediations) {
      if (item.origin === "default") upgradeTemplate(item);
    }
    return tactics;
  }
  return Object.freeze({ defaults: () => JSON.parse(JSON.stringify(catalog)), upgradeTemplate, upgradeCatalog });
})();
