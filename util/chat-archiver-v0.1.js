await (async (username, auth) => {
    /**
     *
     * @param {string} auth Authorization token (OAuth Bearer)
     * @param {Array} body GraphQL query to be sent, as array of objects
     * @returns
     */
    function requestTemplate(auth, body) {
        return {
            method: 'POST',
            credentials: 'same-origin',
            mode: 'cors',
            headers: {
                'Client-Id': 'kimne78kx3ncx6brgo4mv6wki5h1ko',
                Authorization: auth,
                'Content-Type': 'text/plain;charset=UTF-8',
            },
            body: JSON.stringify(body),
        }
    }
    /**
     *
     * @param {string} username Username to return the user ID for
     * @param {string} auth Authorization token (OAuth Bearer)
     * @returns
     */
    async function getUserId(username, auth) {
        let res = await fetch(
            'https://gql.twitch.tv/gql',
            requestTemplate(auth, [
                {
                    operationName: 'GetUserID',
                    variables: { login: username, lookupType: 'ACTIVE' },
                    extensions: {
                        persistedQuery: {
                            version: 1,
                            sha256Hash: 'bf6c594605caa0c63522f690156aa04bd434870bf963deb76668c381d16fcaa5',
                        },
                    },
                },
            ])
        )
        let data = (await res.json())[0]
        return data.data.user.id
    }
    /**
     *
     * @param {string} userId
     * @param {string} auth
     * @param {string} cursor
     * @returns {RequestInit}
     */
    function msgFetchTemplate(userId, auth, cursor = null) {
        return requestTemplate(auth, [
            {
                operationName: 'ViewerCardModLogsMessagesBySender',
                variables: {
                    senderID: userId,
                    channelLogin: 'dougdougw',
                    cursor: cursor,
                },
                extensions: {
                    persistedQuery: {
                        version: 1,
                        sha256Hash: '4186e5c334c3cf17faf912a172aca6b445374b0321eb85a70fb06a81e3c7cf1a',
                    },
                },
            },
        ])
    }
    /**
     *
     * @param {Response} response
     * @returns {Promise<Array>}
     */
    async function processPayload(response) {
        let payload = await response.json()
        let data = payload[0]
        return data.data.channel.modLogs.messagesBySender.edges
    }
    /**
     *
     * @param {Array} edges
     * @returns {string}
     */
    function getCursor(edges) {
        return edges[edges.length - 1].cursor
    }
    var __messages = []
    let cursor = null
    let userId = await getUserId(username)
    while (true) {
        let req = msgFetchTemplate(userId, auth, cursor)
        let msgs = await processPayload(await fetch('https://gql.twitch.tv/gql', req))
        __messages.push(...msgs)
        console.log(`${__messages.length} messages so far ...`)
        try {
            cursor = getCursor(msgs)
        } catch (e) {
            console.log('End of data stream. Stopping ...')
            break
        }
    }
    let result = JSON.stringify(__messages)
    let anchor = document.createElement('a')
    anchor.download = 'messages.json'
    let blob = new Blob([result], { type: 'text/plain' })
    anchor.href = URL.createObjectURL(blob)
    anchor.click()
    return __messages
})(null, null)
