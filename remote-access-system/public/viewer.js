// viewer.js — runs on the VIEWER's browser (the person the link was shared with)

const socket = io();
const $ = (id) => document.getElementById(id);

const params = new URLSearchParams(window.location.search);
const token = params.get('token');
let peerConnection = null;

if (!token) {
  $('result').textContent = 'This link is missing a valid session token.';
  $('result').className = 'status danger';
  $('requestBtn').disabled = true;
}

$('requestBtn').addEventListener('click', () => {
  $('preConnect').style.display = 'none';
  $('waiting').style.display = 'block';
  socket.emit('viewer-request-access', { token });
});

socket.on('access-approved', async () => {
  $('waiting').textContent = 'Approved — connecting…';

  peerConnection = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
  });

  peerConnection.ontrack = (event) => {
    const video = $('remoteVideo');
    video.srcObject = event.streams[0];
    video.style.display = 'block';
    $('waiting').style.display = 'none';
  };

  peerConnection.onicecandidate = (event) => {
    if (event.candidate) {
      socket.emit('webrtc-signal', {
        token,
        targetSocketId: hostSocketIdPlaceholder(),
        signal: { type: 'ice-candidate', candidate: event.candidate }
      });
    }
  };
});

// The host's socket id is only known once we receive their offer; we relay
// through the room (token), so we store it upon first signal from them.
let hostSocketId = null;
function hostSocketIdPlaceholder() { return hostSocketId; }

socket.on('webrtc-signal', async ({ signal, from }) => {
  hostSocketId = from;
  if (signal.type === 'offer') {
    await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.sdp));
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    socket.emit('webrtc-signal', {
      token,
      targetSocketId: from,
      signal: { type: 'answer', sdp: answer }
    });
  } else if (signal.type === 'ice-candidate') {
    try { await peerConnection.addIceCandidate(signal.candidate); } catch (e) { /* ignore */ }
  }
});

socket.on('access-denied', () => {
  $('waiting').style.display = 'none';
  $('result').textContent = 'The host denied this request.';
  $('result').className = 'status danger';
});

socket.on('error-message', (msg) => {
  $('waiting').style.display = 'none';
  $('result').textContent = msg;
  $('result').className = 'status danger';
});

socket.on('session-ended', () => {
  if (peerConnection) { peerConnection.close(); peerConnection = null; }
  $('remoteVideo').style.display = 'none';
  $('result').textContent = 'Session ended by host.';
  $('result').className = 'status';
});

socket.on('session-revoked', () => {
  $('result').textContent = 'This link was revoked by the host.';
  $('result').className = 'status danger';
});
