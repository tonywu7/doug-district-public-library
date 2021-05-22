/**
 *
 * @param {string} text
 * @param {string} sep
 * @param {number | undefined} limit
 * @param {RegExp} toStrip
 * @returns {string}
 */
function slugify(text, sep = '-', limit = undefined, toStrip = /[\W_]+/g) {
    return text.replace(toStrip, ' ').trim().split(' ').slice(0, limit).join(sep).toLowerCase()
}

/**
 *
 * @param {HTMLTableElement} table
 */
function initTableTooltips(table) {
    let headers = table.tHead.rows[1].cells
    let body = table.tBodies.item(0)
    for (let row of body.rows) {
        let permName = document.createElement('b')
        permName.innerText = row.cells[0].innerText
        for (let i = 1; i < row.cells.length; i++) {
            let cell = row.cells[i]
            let tooltip = document.createElement('span')
            tooltip.classList.add('popper-tooltip')
            let roleName = headers[i].innerHTML
            let value = cell.querySelector('i')
            if (!value) continue
            let tooltipHTML = `${roleName} ${value.outerHTML} ${permName.outerHTML}`
            tooltip.innerHTML = tooltipHTML
            cell.appendChild(tooltip)
            let allowed = value.classList.contains('perm-allow')
            if (allowed) {
                cell.classList.add('perm-allow-deco')
            } else {
                cell.classList.add('perm-deny-deco')
            }
        }
    }
}

window.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('h1, h2, h3, .for-approval').forEach((elem) => {
        elem.id = slugify(elem.textContent, '-', 10)
    })

    document.querySelectorAll('.table-title-defer').forEach((elem) => {
        let container = elem.parentElement
        let table = container.querySelector('table')
        let numColumns = table.tHead.rows[0].cells.length
        let tr = document.createElement('tr')
        tr.classList.add('table-title')
        let th = document.createElement('th')
        th.colSpan = numColumns
        th.appendChild(elem)
        tr.appendChild(th)
        table.tHead.prepend(tr)
    })

    document.querySelectorAll('table.dataframe').forEach(initTableTooltips)

    tocbot.init({
        tocSelector: '.for-approval-list',
        contentSelector: 'article',
        headingSelector: 'strong.for-approval',
        hasInnerContainers: false,
        collapseDepth: 3,
        includeHtml: true,
    })

    tocbot.init({
        tocSelector: '.toc',
        contentSelector: 'article',
        headingSelector: 'h2, h3, h4',
        hasInnerContainers: true,
        collapseDepth: 3,
        includeHtml: true,
    })

    /** @type {HTMLElement} */
    let tocToggle = document.querySelector('.toc-toggle')
    tocToggle.addEventListener('click', () => {
        /** @type {HTMLElement} */
        let toc = document.querySelector('.toc')
        let hidden = toc.classList.toggle('hidden')
        if (hidden) tocToggle.textContent = '[show menu]'
        else tocToggle.textContent = '[hide menu]'
    })
})
