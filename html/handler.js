// property of nyrakon
// for developers: this website was made using raw html/js/css, with no fancy libraries, 0 npm, 0 react.
const topbar=document.createElement("iframe")
topbar.className="topbar"
topbar.src="topbar.html"
topbar.setAttribute("seamless",true)
topbar.frameBorder=0

const styles=document.createElement("link")
styles.rel="stylesheet"
styles.href="styles.css"
document.head.append(styles)

const jqSCR=document.createElement("script")
jqSCR.src="https://code.jquery.com/jquery-4.0.0.slim.min.js"
jqSCR.integrity="sha256-8DGpv13HIm+5iDNWw1XqxgFB4mj+yOKFNb+tHBZOowc="
jqSCR.crossOrigin="anonymous"
document.head.append(jqSCR)

const axiosSCR=document.createElement("script")
axiosSCR.src="https://cdn.jsdelivr.net/npm/axios@1.13.2/dist/axios.min.js"
document.head.append(axiosSCR)
function insertMetaTags() {
    const metas = [
        { charset: "UTF-8" },
        { name: "viewport", content: "width=device-width, initial-scale=1.0" },
        { name: "description", content: "Nyrakon provides secure, high-performance infrastructure and cloud systems built for privacy, speed, and scalability." },
        { name: "keywords", content: "cloud infrastructure, private hosting, secure servers, VPS, infrastructure solutions, IaaS" },
        { name: "author", content: "Nyrakon" },
        { name: "robots", content: "index, follow" },
        { property: "og:title", content: "Nyrakon – Private Infrastructure & Cloud Systems" },
        { property: "og:description", content: "Affordable high-performance VPS hosting starting at $1/month." },
        { property: "og:type", content: "website" }
    ];

    for (const metaData of metas) {
        const meta = document.createElement("meta");
        for (const key in metaData) {
            meta.setAttribute(key, metaData[key]);
        }
        // Prevent duplicates (except charset, which should only exist once)
        if (metaData.name) {
            if (document.querySelector(`meta[name="${metaData.name}"]`)) continue;
        }
        if (metaData.property) {
            if (document.querySelector(`meta[property="${metaData.property}"]`)) continue;
        }
        if (metaData.charset) {
            if (document.querySelector("meta[charset]")) continue;
        }
        document.head.appendChild(meta);
    }
}
insertMetaTags();

function cleaninserttopbar(){
    var iframeDoc = topbar.contentWindow.document;
    while (iframeDoc.head.firstChild) {
        document.head.appendChild(iframeDoc.head.firstChild);
    }
    var content = $(".content");
    while (iframeDoc.body.firstChild) {
        content.before(iframeDoc.body.firstChild);
    }
    topbar.remove();
}
jqSCR.onload=()=>{ // insert our topbar
    console.log("jquery loaded")
    document.body.append(topbar)
}
if (topbar.contentWindow===null){
    topbar.onload=()=>{
        cleaninserttopbar()

        // topbar stuff
        $(document).on("click", "#registerbtn", function() {
            document.location.href="/register.html"
        });
        $(document).on("click", "#loginbtn", function() {
            document.location.href="/login.html"
        });
        $(document).on("click", "#signoutbtn", function() {
            cookieStore.delete('session');
            document.location.href="/"
        });
        if (document.cookie.includes("session")) { 
            $(".accountmanagementstuff").hide() // - hide register/login if already logged in
        } else {
            $(".pre-existingacc").hide()
        }
    }
} else {
    cleaninserttopbar()
}

function waitforscripts(fn) {
    var waitForLoad = function () {
        if ((typeof jQuery != "undefined") && (typeof axios != "undefined")) {
            fn()
        } else {
            window.setTimeout(waitForLoad, 50); // Check again in 50 milliseconds
        }
    };
    //window.setTimeout(waitForLoad, 50);
    waitForLoad()
}