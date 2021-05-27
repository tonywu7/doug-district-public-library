let webhookURL =
    'https://discord.com/api/webhooks/847582826479484978/RG-XGIf1fH816p6_LeZHEz87xm-JlVzRhrCgppz4Wob9cR0Ir9hDvGnWRWk0VGUaTmtR'

let appealForm = {
    Timestamp: 'timestamp',
    'Email Address': 'email',
    'Where were you banned? ': 'platform',
    'What is your username on Discord?': 'usernameDiscord',
    'When were you banned?': 'banDate',
    'Why were you banned?': 'banReason',
    'Do you think your ban was deserved? And why?': 'banJustify',
    'Why should we unban you?': 'unbanReason',
    "What's the best way to contact you?": 'contactMethods',
    'What is your username on the platform?': 'username',
    'What is your Discord user ID (if you know it)?': 'idDiscord',
}
let questions = Object.assign(...Object.entries(appealForm).map(([k, v]) => ({ [v]: k })))

class BanAppeal {
    constructor(row, locator) {
        this.cellLocator = locator
        for (let [k, v] of Object.entries(appealForm)) {
            this[v] = row[k]
        }
    }
    get preferredName() {
        return this.usernameDiscord || this.username
    }
    get cooldownPassed() {
        return new Date() - this.banDate >= 1209600000
    }
    toDateInfo() {
        return [
            {
                name: 'Date submitted',
                value: this.timestamp.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'full' }),
            },
            {
                name: 'Date banned',
                value: this.banDate.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
                inline: true,
            },
            {
                name: 'Cooldown passed?',
                value: this.cooldownPassed ? '✅ yes' : '🚫 no',
                inline: true,
            },
        ]
    }
    toUserInfo() {
        let info = [
            {
                name: 'Platform',
                value: this.platform,
                inline: false,
            },
            {
                name: 'Username',
                value: this.preferredName,
                inline: true,
            },
        ]
        if (this.idDiscord) {
            info.push({
                name: 'Discord ID',
                value: this.idDiscord,
                inline: true,
            })
        }
        return info
    }
    toSubmission() {
        return [
            {
                name: 'Ban reason',
                value: this.banReason,
                inline: false,
            },
            {
                name: 'Ban deserved?',
                value: this.banJustify,
                inline: false,
            },
            {
                name: 'Unban justification',
                value: this.unbanReason,
                inline: false,
            },
        ]
    }
    toContactPrefs() {
        return [{ name: 'Contact preference', value: this.contactMethods, inline: true }]
    }
    toContact() {
        return [
            {
                name: 'Email',
                value: `[View in sheet](${this.cellLocator()})`,
            },
        ]
    }
    toEmbedTitle() {
        return `Ban Appeal: ${this.platform}`
    }
    toJSON() {
        return {
            username: 'Ban Appeal Submission',
            avatar_url: 'https://cdn.discordapp.com/emojis/725519181319110680.png?v=1',
            embeds: [this.toEmbed()],
        }
    }
    toEmbed() {
        let embed = {
            author: {
                name: this.preferredName,
            },
            color: 0xe74c3c,
            title: this.toEmbedTitle(),
            fields: [
                ...this.toDateInfo(),
                ...this.toUserInfo(),
                ...this.toSubmission(),
                ...this.toContactPrefs(),
                ...this.toContact(),
            ],
            footer: {
                text: 'Notification created',
            },
            timestamp: new Date().toISOString(),
        }
        return embed
    }
}

function doPOST(payload) {
    Logger.log(JSON.stringify(payload))
    UrlFetchApp.fetch(webhookURL, {
        method: 'POST',
        payload: JSON.stringify(payload),
        contentType: 'application/json',
    })
    return true
}

function webhookPOST() {
    let sheets = SpreadsheetApp.getActive().getSheets()
    let incoming = sheets[0]
    let stored = sheets[1]
    let failures = sheets[2]
    let maxRows = incoming.getLastRow()
    let maxCols = incoming.getLastColumn()

    let toStore = []
    let toFailure = []

    if (incoming.getLastRow() == 1) {
        return
    }

    let schema = incoming.getRange(1, 1, 1, maxCols).getValues()[0]
    let entries = incoming.getRange(2, 1, maxRows - 1, maxCols)
    let data = entries.getValues()

    let maxStored = stored.getLastRow()
    let maxFailure = failures.getLastRow()

    function getCellURL(sheet, row) {
        return `${SpreadsheetApp.getActive().getUrl()}#gid=${sheet.getSheetId().toString()}&range=A${row}`
    }

    function notifyFailure(e) {
        return {
            username: 'Ban Appeal Submission',
            content: `Received submission but failed to create a notification\nSee ${getCellURL(
                failures,
                maxFailure + 1
            )}\n${e.toString()}`,
            embeds: [],
        }
    }

    for (let r of data) {
        if (!r[0].toString().length) continue
        let rowData = Object.assign(...schema.map((k, i) => ({ [k]: r[i] })))
        try {
            let appeal = new BanAppeal(rowData, () => getCellURL(stored, maxStored + 1))
            let payload = appeal.toJSON()
            doPOST(payload)
            maxStored += 1
            toStore.push(r)
        } catch (e) {
            toFailure.push([...r, e.toString()])
            try {
                doPOST(notifyFailure(e))
            } catch (e) {}
            maxFailure += 1
        }
    }

    entries.deleteCells(SpreadsheetApp.Dimension.ROWS)
    toStore.forEach((r) => stored.appendRow(r))
    toFailure.forEach((r) => failures.appendRow(r))
}
