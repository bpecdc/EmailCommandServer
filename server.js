/**
 * DailyOrganizer Email Command Server
 *
 * Receives emails via Mailgun webhook, parses commands, and queues them
 * for the iOS app to fetch and execute.
 */

const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const upload = multer();

// Middleware pour parser les formulaires URL-encoded
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    // Port du serveur
    PORT: process.env.PORT || 3000,

    // Clé API Mailgun pour vérifier la signature des webhooks
    MAILGUN_API_KEY: process.env.MAILGUN_API_KEY || 'your-mailgun-api-key',

    // Clé secrète pour l'API iOS (à générer et garder secrète)
    IOS_API_KEY: process.env.IOS_API_KEY || 'your-ios-api-key',

    // Liste des expéditeurs autorisés (emails)
    AUTHORIZED_SENDERS: (process.env.AUTHORIZED_SENDERS || '').split(',').filter(e => e.trim()),

    // Fichier de stockage des commandes (en production, utiliser une vraie DB)
    COMMANDS_FILE: path.join(__dirname, 'data', 'commands.json'),

    // Durée de rétention des commandes traitées (en jours)
    RETENTION_DAYS: 7,

    // Configuration Mailgun pour l'envoi d'emails de réponse
    MAILGUN_DOMAIN: process.env.MAILGUN_DOMAIN || 'sandboxc257728c07b4417ebde91e498cd59dc6.mailgun.org',
    MAILGUN_SENDING_KEY: process.env.MAILGUN_SENDING_KEY || '', // Clé API pour l'envoi (différente de la webhook key)
    MAILGUN_FROM_EMAIL: process.env.MAILGUN_FROM_EMAIL || 'DailyOrganizer <commands@sandboxc257728c07b4417ebde91e498cd59dc6.mailgun.org>'
};

// Créer le dossier data s'il n'existe pas
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// ============================================================================
// TYPES DE COMMANDES
// ============================================================================

const CommandType = {
    PLANNING: 'PLANNING',           // Afficher/extraire le planning d'un jour
    ADD_EVENT: 'ADD_EVENT',         // Ajouter un événement planifié
    ADD_IDEA: 'ADD_IDEA',           // Ajouter une idée
    ADD_QUEUE: 'ADD_QUEUE',         // Ajouter à la file d'attente
    HELP: 'HELP',                   // Afficher l'aide
    STATUS: 'STATUS',               // Afficher le statut actuel
    UNKNOWN: 'UNKNOWN'              // Commande non reconnue
};

const CommandStatus = {
    PENDING: 'pending',             // En attente de traitement par l'app
    ACCEPTED: 'accepted',           // Acceptée par l'utilisateur
    REJECTED: 'rejected',           // Rejetée par l'utilisateur
    EXECUTED: 'executed',           // Exécutée avec succès
    FAILED: 'failed',               // Échec de l'exécution
    EXPIRED: 'expired'              // Expirée (non traitée à temps)
};

// ============================================================================
// STOCKAGE DES COMMANDES
// ============================================================================

function loadCommands() {
    try {
        if (fs.existsSync(CONFIG.COMMANDS_FILE)) {
            const data = fs.readFileSync(CONFIG.COMMANDS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (error) {
        console.error('Erreur lors du chargement des commandes:', error);
    }
    return [];
}

function saveCommands(commands) {
    try {
        fs.writeFileSync(CONFIG.COMMANDS_FILE, JSON.stringify(commands, null, 2));
    } catch (error) {
        console.error('Erreur lors de la sauvegarde des commandes:', error);
    }
}

function addCommand(command) {
    const commands = loadCommands();
    commands.push(command);
    saveCommands(commands);
    return command;
}

function updateCommand(commandId, updates) {
    const commands = loadCommands();
    const index = commands.findIndex(c => c.id === commandId);
    if (index !== -1) {
        commands[index] = { ...commands[index], ...updates, updatedAt: new Date().toISOString() };
        saveCommands(commands);
        return commands[index];
    }
    return null;
}

function cleanupOldCommands() {
    const commands = loadCommands();
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - CONFIG.RETENTION_DAYS);

    const filteredCommands = commands.filter(cmd => {
        const cmdDate = new Date(cmd.createdAt);
        // Garder les commandes récentes ou en attente
        return cmdDate > cutoffDate || cmd.status === CommandStatus.PENDING;
    });

    if (filteredCommands.length !== commands.length) {
        saveCommands(filteredCommands);
        console.log(`Nettoyage: ${commands.length - filteredCommands.length} commandes supprimées`);
    }
}

// ============================================================================
// PARSING DES COMMANDES
// ============================================================================

/**
 * Parse une date au format DD/MM/YYYY
 */
function parseDate(dateStr) {
    if (!dateStr) return null;

    const match = dateStr.trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (!match) return null;

    const [, day, month, year] = match;
    const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));

    // Vérifier que la date est valide
    if (isNaN(date.getTime())) return null;

    return date.toISOString().split('T')[0]; // Format YYYY-MM-DD
}

/**
 * Parse une heure au format HH:MM
 */
function parseTime(timeStr) {
    if (!timeStr) return null;

    const match = timeStr.trim().match(/^(\d{1,2}):(\d{2})$/);
    if (!match) return null;

    const [, hours, minutes] = match;
    const h = parseInt(hours);
    const m = parseInt(minutes);

    if (h < 0 || h > 23 || m < 0 || m > 59) return null;

    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`;
}

/**
 * Parse le contenu d'un email et extrait la commande
 */
function parseEmailCommand(subject, body) {
    // Nettoyer le sujet et le corps
    const cleanSubject = (subject || '').trim().toUpperCase();
    const cleanBody = (body || '').trim();

    // Combiner sujet et corps pour l'analyse
    const fullText = cleanSubject || cleanBody.split('\n')[0].toUpperCase();

    // -------------------------------------------------------------------------
    // COMMANDE: AIDE / HELP
    // -------------------------------------------------------------------------
    if (fullText.match(/^(AIDE|HELP)$/i)) {
        return {
            type: CommandType.HELP,
            data: {},
            requiresApproval: false,
            description: "Demande d'aide - liste des commandes disponibles"
        };
    }

    // -------------------------------------------------------------------------
    // COMMANDE: STATUS
    // -------------------------------------------------------------------------
    if (fullText.match(/^(STATUS|STATUT|ETAT)$/i)) {
        return {
            type: CommandType.STATUS,
            data: {},
            requiresApproval: false,
            description: "Demande de statut actuel"
        };
    }

    // -------------------------------------------------------------------------
    // COMMANDE: PLANNING <date>
    // Formats acceptés: "PLANNING 10/09/2026" ou "PLANNING DEMAIN" ou "PLANNING AUJOURD'HUI"
    // -------------------------------------------------------------------------
    const planningMatch = fullText.match(/^PLANNING\s+(.+)$/i);
    if (planningMatch) {
        let dateStr = planningMatch[1].trim();
        let targetDate;

        if (dateStr.match(/^(AUJOURD'?HUI|TODAY)$/i)) {
            targetDate = new Date().toISOString().split('T')[0];
        } else if (dateStr.match(/^(DEMAIN|TOMORROW)$/i)) {
            const tomorrow = new Date();
            tomorrow.setDate(tomorrow.getDate() + 1);
            targetDate = tomorrow.toISOString().split('T')[0];
        } else {
            targetDate = parseDate(dateStr);
        }

        if (targetDate) {
            return {
                type: CommandType.PLANNING,
                data: { date: targetDate },
                requiresApproval: false,
                description: `Afficher le planning du ${targetDate}`
            };
        }
    }

    // -------------------------------------------------------------------------
    // COMMANDE: AJOUTER | Titre | Date | Heure début | Heure fin
    // Format: "AJOUTER | Rendez-vous dentiste | 10/09/2026 | 14:00 | 15:00"
    // -------------------------------------------------------------------------
    const addEventMatch = fullText.match(/^AJOUTER\s*\|/i);
    if (addEventMatch) {
        const parts = fullText.split('|').map(p => p.trim());

        if (parts.length >= 4) {
            const title = parts[1];
            const date = parseDate(parts[2]);
            const startTime = parseTime(parts[3]);
            const endTime = parts[4] ? parseTime(parts[4]) : null;

            if (title && date && startTime) {
                return {
                    type: CommandType.ADD_EVENT,
                    data: {
                        title: title,
                        date: date,
                        startTime: startTime,
                        endTime: endTime,
                        note: cleanBody || null
                    },
                    requiresApproval: true,
                    description: `Ajouter "${title}" le ${date} à ${startTime}${endTime ? ` - ${endTime}` : ''}`
                };
            }
        }
    }

    // -------------------------------------------------------------------------
    // COMMANDE: IDEE | Titre | Durée (optionnel)
    // Format: "IDEE | Apprendre le piano | 30" (durée en minutes)
    // -------------------------------------------------------------------------
    const addIdeaMatch = fullText.match(/^(IDEE|IDEA)\s*\|/i);
    if (addIdeaMatch) {
        const parts = fullText.split('|').map(p => p.trim());

        if (parts.length >= 2) {
            const title = parts[1];
            const durationMinutes = parts[2] ? parseInt(parts[2]) : 30;

            if (title) {
                return {
                    type: CommandType.ADD_IDEA,
                    data: {
                        title: title,
                        durationMinutes: isNaN(durationMinutes) ? 30 : durationMinutes,
                        note: cleanBody || null
                    },
                    requiresApproval: true,
                    description: `Ajouter l'idée "${title}" (${durationMinutes} min)`
                };
            }
        }
    }

    // -------------------------------------------------------------------------
    // COMMANDE: QUEUE | Titre | Durée (optionnel)
    // Format: "QUEUE | Faire les courses | 45"
    // -------------------------------------------------------------------------
    const addQueueMatch = fullText.match(/^(QUEUE|FILE)\s*\|/i);
    if (addQueueMatch) {
        const parts = fullText.split('|').map(p => p.trim());

        if (parts.length >= 2) {
            const title = parts[1];
            const durationMinutes = parts[2] ? parseInt(parts[2]) : 30;

            if (title) {
                return {
                    type: CommandType.ADD_QUEUE,
                    data: {
                        title: title,
                        durationMinutes: isNaN(durationMinutes) ? 30 : durationMinutes,
                        note: cleanBody || null
                    },
                    requiresApproval: true,
                    description: `Ajouter à la file "${title}" (${durationMinutes} min)`
                };
            }
        }
    }

    // -------------------------------------------------------------------------
    // COMMANDE NON RECONNUE
    // -------------------------------------------------------------------------
    return {
        type: CommandType.UNKNOWN,
        data: {
            originalSubject: subject,
            originalBody: body
        },
        requiresApproval: false,
        description: "Commande non reconnue"
    };
}

// ============================================================================
// VÉRIFICATION MAILGUN
// ============================================================================

/**
 * Vérifie la signature Mailgun pour s'assurer que le webhook est authentique
 * @param {string} timestamp - Timestamp Unix du webhook
 * @param {string} token - Token unique généré par Mailgun
 * @param {string} signature - Signature HMAC-SHA256 à vérifier
 * @returns {boolean} - true si la signature est valide
 */
function verifyMailgunSignature(timestamp, token, signature) {
    // En mode dev (clé non configurée), on accepte sans vérification
    if (!CONFIG.MAILGUN_API_KEY || CONFIG.MAILGUN_API_KEY === 'your-mailgun-api-key') {
        console.warn('ATTENTION: Clé API Mailgun non configurée, signature non vérifiée');
        return true;
    }

    // Vérifier que tous les champs requis sont présents
    if (!timestamp || !token || !signature) {
        console.error('Champs de signature Mailgun manquants:', {
            hasTimestamp: !!timestamp,
            hasToken: !!token,
            hasSignature: !!signature
        });
        return false;
    }

    // Mailgun attend HMAC-SHA256 de (timestamp + token), tout en string
    const data = String(timestamp) + String(token);

    const hmac = crypto.createHmac('sha256', CONFIG.MAILGUN_API_KEY);
    hmac.update(data, 'utf8');
    const expectedSignature = hmac.digest('hex');

    const isValid = expectedSignature === signature;

    if (!isValid) {
        console.error('Signature Mailgun invalide:', {
            expected: expectedSignature.substring(0, 10) + '...',
            received: signature ? signature.substring(0, 10) + '...' : 'null'
        });
    }

    return isValid;
}

/**
 * Vérifie si l'expéditeur est autorisé
 */
function isAuthorizedSender(sender) {
    if (CONFIG.AUTHORIZED_SENDERS.length === 0) {
        console.warn('ATTENTION: Aucun expéditeur autorisé configuré, tous les emails sont acceptés');
        return true; // En dev, on accepte tout
    }

    // Extraire l'email de l'adresse (format "Nom <email@domain.com>" ou "email@domain.com")
    const emailMatch = sender.match(/<([^>]+)>/) || [null, sender];
    const email = emailMatch[1].toLowerCase().trim();

    return CONFIG.AUTHORIZED_SENDERS.some(authorized =>
        authorized.toLowerCase().trim() === email
    );
}

// ============================================================================
// ENVOI D'EMAILS DE RÉPONSE
// ============================================================================

/**
 * Extrait l'adresse email pure d'un format "Nom <email>" ou "email"
 */
function extractEmail(sender) {
    const emailMatch = sender.match(/<([^>]+)>/) || [null, sender];
    return emailMatch[1].trim();
}

/**
 * Envoie un email de réponse via l'API Mailgun
 * @param {string} to - Adresse email du destinataire
 * @param {string} subject - Sujet de l'email
 * @param {string} text - Corps du message en texte brut
 * @returns {Promise<boolean>} - true si envoyé avec succès
 */
async function sendResponseEmail(to, subject, text) {
    if (!CONFIG.MAILGUN_SENDING_KEY) {
        console.warn('MAILGUN_SENDING_KEY non configurée, email de réponse non envoyé');
        return false;
    }

    const url = `https://api.mailgun.net/v3/${CONFIG.MAILGUN_DOMAIN}/messages`;

    // Préparer les données du formulaire
    const formData = new URLSearchParams();
    formData.append('from', CONFIG.MAILGUN_FROM_EMAIL);
    formData.append('to', to);
    formData.append('subject', subject);
    formData.append('text', text);

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + Buffer.from('api:' + CONFIG.MAILGUN_SENDING_KEY).toString('base64'),
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: formData.toString()
        });

        if (response.ok) {
            console.log(`Email de réponse envoyé à ${to}`);
            return true;
        } else {
            const errorText = await response.text();
            console.error(`Erreur envoi email: ${response.status} - ${errorText}`);
            return false;
        }
    } catch (error) {
        console.error('Erreur lors de l\'envoi de l\'email:', error);
        return false;
    }
}

/**
 * Génère le contenu de l'email de réponse selon le type et le résultat
 */
function generateResponseContent(command, result) {
    const statusEmoji = command.status === 'executed' ? '✅' : '❌';
    const statusText = command.status === 'executed' ? 'Exécutée' : 'Échouée';

    let subject = `${statusEmoji} Re: ${command.originalSubject || command.type}`;

    let body = `DailyOrganizer - Résultat de votre commande\n`;
    body += `${'─'.repeat(45)}\n\n`;
    body += `Commande: ${command.description}\n`;
    body += `Statut: ${statusText}\n\n`;

    if (result) {
        body += `Résultat:\n${result}\n`;
    }

    body += `\n${'─'.repeat(45)}\n`;
    body += `Envoyé automatiquement par DailyOrganizer`;

    return { subject, body };
}

// ============================================================================
// ROUTES
// ============================================================================

// Middleware pour parser le JSON
app.use(express.json());

// Route de santé
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// -------------------------------------------------------------------------
// WEBHOOK MAILGUN - Réception des emails
// -------------------------------------------------------------------------
app.post('/webhook/mailgun', upload.any(), (req, res) => {
    console.log('=== Réception webhook Mailgun ===');

    // Debug: afficher la structure complète reçue
    console.log('Body keys:', Object.keys(req.body || {}));
    console.log('Body sample:', JSON.stringify(req.body, null, 2).substring(0, 1000));

    try {
        // Extraire les champs directement depuis req.body
        // Mailgun envoie les données en multipart/form-data avec des champs plats
        const sender = req.body.sender || req.body.Sender;
        const from = req.body.from || req.body.From;
        const subject = req.body.subject || req.body.Subject;
        const bodyPlain = req.body['body-plain'] || req.body['Body-plain'] || '';
        const strippedText = req.body['stripped-text'] || req.body['Stripped-text'] || '';
        const timestamp = req.body.timestamp;
        const token = req.body.token;
        const signature = req.body.signature;

        const senderEmail = sender || from;
        const emailBody = strippedText || bodyPlain || '';

        console.log(`De: ${senderEmail}`);
        console.log(`Sujet: ${subject}`);
        console.log(`Timestamp: ${timestamp}, Token: ${token ? 'present' : 'missing'}, Signature: ${signature ? 'present' : 'missing'}`);

        // Vérifier la signature Mailgun
        if (!verifyMailgunSignature(timestamp, token, signature)) {
            console.error('Signature Mailgun invalide');
            return res.status(401).json({ error: 'Invalid signature' });
        }

        // Vérifier l'expéditeur
        if (!isAuthorizedSender(senderEmail)) {
            console.warn(`Expéditeur non autorisé: ${senderEmail}`);
            return res.status(403).json({ error: 'Unauthorized sender' });
        }

        // Parser la commande
        const parsedCommand = parseEmailCommand(subject, emailBody);

        // Créer l'objet commande
        const command = {
            id: uuidv4(),
            type: parsedCommand.type,
            data: parsedCommand.data,
            description: parsedCommand.description,
            requiresApproval: parsedCommand.requiresApproval,
            status: CommandStatus.PENDING,
            sender: senderEmail,
            originalSubject: subject,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        // Sauvegarder la commande
        addCommand(command);

        console.log(`Commande créée: ${command.id} (${command.type})`);

        // Répondre à Mailgun
        res.status(200).json({
            success: true,
            commandId: command.id,
            type: command.type
        });

    } catch (error) {
        console.error('Erreur lors du traitement du webhook:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// -------------------------------------------------------------------------
// API iOS - Récupérer les commandes en attente
// -------------------------------------------------------------------------
app.get('/api/commands/pending', (req, res) => {
    // Vérifier la clé API
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== CONFIG.IOS_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    const commands = loadCommands();
    const pendingCommands = commands.filter(c => c.status === CommandStatus.PENDING);

    res.json({
        success: true,
        commands: pendingCommands,
        count: pendingCommands.length
    });
});

// -------------------------------------------------------------------------
// API iOS - Récupérer toutes les commandes (avec filtre optionnel)
// -------------------------------------------------------------------------
app.get('/api/commands', (req, res) => {
    // Vérifier la clé API
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== CONFIG.IOS_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    const { status, limit } = req.query;
    let commands = loadCommands();

    // Filtrer par statut si spécifié
    if (status) {
        commands = commands.filter(c => c.status === status);
    }

    // Limiter le nombre de résultats
    if (limit) {
        commands = commands.slice(0, parseInt(limit));
    }

    // Trier par date de création (plus récent en premier)
    commands.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    res.json({
        success: true,
        commands: commands,
        count: commands.length
    });
});

// -------------------------------------------------------------------------
// API iOS - Mettre à jour le statut d'une commande
// -------------------------------------------------------------------------
app.patch('/api/commands/:id', async (req, res) => {
    // Vérifier la clé API
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== CONFIG.IOS_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    const { id } = req.params;
    const { status, result } = req.body;

    // Valider le statut
    if (!Object.values(CommandStatus).includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    const updatedCommand = updateCommand(id, { status, result });

    if (!updatedCommand) {
        return res.status(404).json({ error: 'Command not found' });
    }

    console.log(`Commande ${id} mise à jour: ${status}`);

    // Envoyer un email de réponse si la commande a été exécutée ou a échoué
    if (status === CommandStatus.EXECUTED || status === CommandStatus.FAILED) {
        const recipientEmail = extractEmail(updatedCommand.sender);
        const { subject, body } = generateResponseContent(updatedCommand, result);

        // Envoyer l'email en arrière-plan (ne pas bloquer la réponse)
        sendResponseEmail(recipientEmail, subject, body).catch(err => {
            console.error('Erreur envoi email de réponse:', err);
        });
    }

    res.json({
        success: true,
        command: updatedCommand
    });
});

// -------------------------------------------------------------------------
// API iOS - Supprimer une commande
// -------------------------------------------------------------------------
app.delete('/api/commands/:id', (req, res) => {
    // Vérifier la clé API
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== CONFIG.IOS_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
    }

    const { id } = req.params;
    const commands = loadCommands();
    const filteredCommands = commands.filter(c => c.id !== id);

    if (filteredCommands.length === commands.length) {
        return res.status(404).json({ error: 'Command not found' });
    }

    saveCommands(filteredCommands);

    res.json({ success: true });
});

// -------------------------------------------------------------------------
// Route pour tester le parsing (utile en développement)
// -------------------------------------------------------------------------
app.post('/api/test/parse', (req, res) => {
    const { subject, body } = req.body;
    const parsedCommand = parseEmailCommand(subject, body);

    res.json({
        success: true,
        parsed: parsedCommand
    });
});

// ============================================================================
// DÉMARRAGE DU SERVEUR
// ============================================================================

// Nettoyage périodique des anciennes commandes (toutes les heures)
setInterval(cleanupOldCommands, 60 * 60 * 1000);

// Premier nettoyage au démarrage
cleanupOldCommands();

app.listen(CONFIG.PORT, () => {
    console.log('');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║     DailyOrganizer Email Command Server                    ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log(`║  Port: ${CONFIG.PORT}                                              ║`);
    console.log(`║  Expéditeurs autorisés: ${CONFIG.AUTHORIZED_SENDERS.length || 'TOUS (dev mode)'}                        ║`);
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  Endpoints:                                                ║');
    console.log('║    POST /webhook/mailgun     - Webhook Mailgun             ║');
    console.log('║    GET  /api/commands        - Liste des commandes         ║');
    console.log('║    GET  /api/commands/pending - Commandes en attente       ║');
    console.log('║    PATCH /api/commands/:id   - Mettre à jour une commande  ║');
    console.log('║    DELETE /api/commands/:id  - Supprimer une commande      ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log('');
});

module.exports = app;
