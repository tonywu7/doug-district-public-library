window.addEventListener('DOMContentLoaded', () => {
    tocbot.init({
        // Where to render the table of contents.
        tocSelector: '.toc',
        // Where to grab the headings to build the table of contents.
        contentSelector: 'article',
        // Which headings to grab inside of the contentSelector element.
        headingSelector: 'h2, h3',
        // For headings inside relative or absolute positioned containers within content.
        hasInnerContainers: true,
        collapseDepth: 3,
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
