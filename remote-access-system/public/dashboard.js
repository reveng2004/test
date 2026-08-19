// dashboard.js — runs on the HOST's browser (the account being remoted into)

const socket = io();
let currentToken = null;
let peerConnection = null;
let pendingViewerSocketId = null;

const $ = (id) => document.getElementById(id);

// ---- Load authenticated user info ----
async function loadUser() {
  const res = await fetch('/api/me');
  if (res.status === 401) {
    window.location.href = '/login.html';
    return;
  }
  const user = await res.json();
  $('avatar').src = user.avatar || '';
  $('name').textContent = user.name;
  $('email').textContent = user.email;
}
loadUser();

// ---- Create a unique, time-limited share link ----
$('createLinkBtn').addEventListener('click', async () => {
  const res = await fetch('/api/session/create', { method: 'POST' });
  const data = await res.json();
  currentToken = data.token;

  $('linkText').textContent = data.shareUrl;
  $('expiry').textContent = `Expires in ${data.expiresInMinutes} minutes, single use.`;
  $('linkBox').style.display = 'block';

  // Register this socket as the host for this token so the server can
  // route access requests and signaling to the right browser tab.
  socket.emit('host-register', { token: currentToken });
});

$('revokeBtn').addEventListener('click', async () => {
  if (!currentToken) return;
  await fetch('/api/session/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: currentToken })
  });
  $('linkBox').style.display = 'none';
  $('sessionStatus').textContent = 'Link revoked.';
});

// ---- Someone opened the link and is asking for access ----
socket.on('access-request', ({ viewerSocketId, token }) => {
  pendingViewerSocketId = viewerSocketId;
  $('approvalBox').style.display = 'block';
});

$('approveBtn').addEventListener('click', async () => {
  $('approvalBox').style.display = 'none';
  socket.emit('host-respond', {
    token: currentToken,
    viewerSocketId: pendingViewerSocketId,
    approved: true
  });
  await startScreenShare(pendingViewerSocketId);
});

$('denyBtn').addEventListener('click', () => {
  $('approvalBox').style.display = 'none';
  socket.emit('host-respond', {
    token: currentToken,
    viewerSocketId: pendingViewerSocketId,
    approved: false
  });
  pendingViewerSocketId = null;
});

// ---- WebRTC: host captures its screen and sends it to the viewer ----
async function startScreenShare(viewerSocketId) {
  try {
    const stream = await navigator.mediaDevices.getDisplayMedia({
      video: { cursor: 'always' },
      audio: false
    });

    $('previewVideo').srcObject = stream;
    $('previewVideo').style.display = 'block';
    $('sessionStatus').textContent = 'Sharing screen…';
    $('sessionStatus').className = 'status success';

    peerConnection = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
      // Add a TURN server here for reliability behind restrictive NATs.
    });

    stream.getTracks().forEach((track) => peerConnection.addTrack(track, stream));

    peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        socket.emit('webrtc-signal', {
          token: currentToken,
          targetSocketId: viewerSocketId,
          signal: { type: 'ice-candidate', candidate: event.candidate }
        });
      }
    };

    // If the user clicks the browser's built-in "Stop sharing" button
    stream.getVideoTracks()[0].onended = () => endSession();

    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    socket.emit('webrtc-signal', {
      token: currentToken,
      targetSocketId: viewerSocketId,
      signal: { type: 'offer', sdp: offer }
    });
  } catch (err) {
    $('sessionStatus').textContent = 'Screen share cancelled or failed: ' + err.message;
    $('sessionStatus').className = 'status danger';
  }
}

socket.on('webrtc-signal', async ({ signal, from }) => {
  if (!peerConnection) return;
  if (signal.type === 'answer') {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
  } else if (signal.type === 'ice-candidate') {
    try { await peerConnection.addIceCandidate(signal.candidate); } catch (e) { /* ignore */ }
  }
});

socket.on('session-ended', () => endSession());
socket.on('error-message', (msg) => {
  $('sessionStatus').textContent = msg;
  $('sessionStatus').className = 'status danger';
});

function endSession() {
  if (peerConnection) { peerConnection.close(); peerConnection = null; }
  $('previewVideo').style.display = 'none';
  $('sessionStatus').textContent = 'Session ended.';
  $('sessionStatus').className = 'status';
}

// Let the host end the session manually by closing the tab / revoking link
window.addEventListener('beforeunload', () => {
  if (currentToken) socket.emit('end-session', { token: currentToken });
});
