// Toggle chatbot popup display and change launcher icon
function toggleChatbot() {
    const chatWindow = document.getElementById('chatbotContainer');
    const launcherIcon = document.getElementById('chatLauncherIcon');

    if (!chatWindow) return;

    if (chatWindow.classList.contains('d-none')) {
        chatWindow.classList.remove('d-none');
        if (launcherIcon) launcherIcon.className = 'fa-solid fa-xmark';
    } else {
        chatWindow.classList.add('d-none');
        if (launcherIcon) launcherIcon.className = 'fa-solid fa-robot';
    }
}

// Send chat message to API backend
async function sendChatMessage() {
    const input = document.getElementById('userInput');
    if (!input) return;

    const msg = input.value.trim();
    if (!msg) return;

    const chatContainer = document.getElementById('chatContainer');
    
    // Append User Message Bubble
    chatContainer.innerHTML += `
        <div class="chat-msg-user">
            ${escapeHTML(msg)}
        </div>
    `;
    input.value = '';
    chatContainer.scrollTop = chatContainer.scrollHeight;

    // Append Typing Indicator Placeholder
    const loadingId = 'typing-' + Date.now();
    chatContainer.innerHTML += `
        <div class="chat-msg-bot text-muted" id="${loadingId}">
            <i class="fa-solid fa-spinner fa-spin me-1"></i> Sentinel AI processing...
        </div>
    `;
    chatContainer.scrollTop = chatContainer.scrollHeight;

    try {
        const response = await fetch('/api/chatbot', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
        });
        
        const data = await response.json();
        const loadingElem = document.getElementById(loadingId);
        
        if (loadingElem) {
            loadingElem.outerHTML = `
                <div class="chat-msg-bot chat-report">
                    ${escapeHTML(data.response).replace(/\*\*(.*?)\*\*/g, '$1')}
                </div>
            `;
        }
    } catch (error) {
        const loadingElem = document.getElementById(loadingId);
        if (loadingElem) {
            loadingElem.outerHTML = `
                <div class="chat-msg-bot text-danger">
                    <i class="fa-solid fa-triangle-exclamation me-1"></i> Connection lost to risk intelligence engine.
                </div>
            `;
        }
    }
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

// Trigger message submission on Enter key
document.addEventListener('DOMContentLoaded', () => {
    const userInput = document.getElementById('userInput');
    if (userInput) {
        userInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });
    }
});

// Helper function to sanitize user inputs
function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
}