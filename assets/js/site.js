// ═══════════════ PARTICLES ═══════════════
const canvas = document.getElementById('particles-canvas');
const ctx = canvas.getContext('2d');
let particles = [];
let mouseX = -1000, mouseY = -1000;
window.addEventListener('mousemove', (e) => { mouseX = e.clientX; mouseY = e.clientY; });

function resizeCanvas() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

class Particle {
    constructor() { this.reset(); }
    reset() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.size = Math.random() * 2 + 0.5;
        this.speedX = (Math.random() - 0.5) * 0.5;
        this.speedY = (Math.random() - 0.5) * 0.5;
        this.opacity = Math.random() * 0.5 + 0.1;
        this.hue = Math.random() > 0.7 ? 160 : 140;
    }
    update() {
        this.x += this.speedX; this.y += this.speedY;
        if (this.x < 0 || this.x > canvas.width || this.y < 0 || this.y > canvas.height) this.reset();
        const dx = mouseX - this.x, dy = mouseY - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 100) { this.x -= dx * 0.01; this.y -= dy * 0.01; this.opacity = Math.min(this.opacity + 0.02, 0.8); }
    }
    draw() {
        ctx.beginPath(); ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${this.hue}, 100%, 50%, ${this.opacity})`; ctx.fill();
        ctx.beginPath(); ctx.arc(this.x, this.y, this.size * 2, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${this.hue}, 100%, 50%, ${this.opacity * 0.2})`; ctx.fill();
    }
}
for (let i = 0; i < 80; i++) particles.push(new Particle());

function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 120) {
                ctx.beginPath(); ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(0, 255, 136, ${0.1 * (1 - dist / 120)})`; ctx.lineWidth = 0.5; ctx.stroke();
            }
        }
    }
}
function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach(p => { p.update(); p.draw(); });
    drawConnections();
    requestAnimationFrame(animateParticles);
}
animateParticles();

// ═══════════════ DRAGON CURSOR ═══════════════
const cursorDot = document.getElementById('cursor-dot');
const cursorClaw = document.getElementById('cursor-claw');
let cMouseX = 0, cMouseY = 0, lastEmberX = 0, lastEmberY = 0;
const HEX_CHARS = '0123456789ABCDEF';

function spawnEmber(x, y) {
    const ember = document.createElement('span');
    ember.className = 'hex-ember';
    ember.textContent = '0x' + HEX_CHARS[Math.floor(Math.random()*16)] + HEX_CHARS[Math.floor(Math.random()*16)];
    ember.style.left = (x + Math.random() * 16 - 8) + 'px';
    ember.style.top = (y + Math.random() * 10 - 5) + 'px';
    ember.style.setProperty('--ember-dx', (Math.random() * 24 - 12) + 'px');
    document.body.appendChild(ember);
    setTimeout(() => ember.remove(), 950);
}

document.addEventListener('mousemove', e => {
    const dx = e.clientX - cMouseX, dy = e.clientY - cMouseY;
    cMouseX = e.clientX; cMouseY = e.clientY;
    cursorDot.style.left = (cMouseX - 3) + 'px';
    cursorDot.style.top = (cMouseY - 3) + 'px';
    cursorClaw.style.left = (cMouseX - 19) + 'px';
    cursorClaw.style.top = (cMouseY - 19) + 'px';
    if (Math.abs(dx) > 1 || Math.abs(dy) > 1)
        cursorClaw.style.transform = `rotate(${Math.atan2(dy, dx) * 180 / Math.PI}deg)`;
    if (Math.hypot(cMouseX - lastEmberX, cMouseY - lastEmberY) > 28) {
        spawnEmber(cMouseX, cMouseY);
        lastEmberX = cMouseX; lastEmberY = cMouseY;
    }
});

document.querySelectorAll('a,button,.skill-card,.project-card,.cert-card,.blog-item').forEach(el => {
    el.addEventListener('mouseenter', () => cursorClaw.classList.add('hover'));
    el.addEventListener('mouseleave', () => cursorClaw.classList.remove('hover'));
});

// ═══════════════ NAVIGATION ═══════════════
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => { navbar.classList.toggle('scrolled', window.scrollY > 50); });
const mobileToggleBtn = document.getElementById('mobile-toggle');
if (mobileToggleBtn) {
    mobileToggleBtn.addEventListener('click', () => {
        document.getElementById('nav-links').classList.toggle('active');
    });
}
document.querySelectorAll('#nav-links a').forEach(link => {
    link.addEventListener('click', () => document.getElementById('nav-links').classList.remove('active'));
});

// ═══════════════ SCROLL ANIMATIONS ═══════════════
if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, i) => {
            if (entry.isIntersecting) {
                setTimeout(() => entry.target.classList.add('visible'), i * 70);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.05, rootMargin: '0px 0px -30px 0px' });
    document.querySelectorAll('.animate-on-scroll').forEach(el => observer.observe(el));
} else {
    document.querySelectorAll('.animate-on-scroll').forEach(el => el.classList.add('visible'));
}

// ═══════════════ SMOOTH SCROLL (same-page anchors only) ═══════════════
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        const targetId = this.getAttribute('href');
        if (!targetId || targetId.length < 2) return;
        const target = document.querySelector(targetId);
        if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});

// ═══════════════ CONSOLE ═══════════════
console.log('%c0xdragon — Offensive Security & Research', 'color:#00ff88;font-size:16px;font-weight:700');
