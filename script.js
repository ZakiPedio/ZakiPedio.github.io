// script.js
// Enhanced stealth terminal (externalized)
// NOTE: keep this file in UTF-8. Do not include surrounding <script> tags when saved.

(() => {
  // Run when DOM is ready so getElementById/etc. succeed
  document.addEventListener('DOMContentLoaded', () => {

    // DOM elements (guarded)
    const output = document.getElementById('output');
    const form = document.getElementById('cmdform');
    const input = document.getElementById('cmd');

    if (!output || !form || !input) {
      // If expected markup isn't present, stop. This helps avoid console errors.
      console.warn('terminal: missing required DOM elements (#output, #cmdform, #cmd).');
      return;
    }

    // -- state & content (edit these) --
    const STATE = {
      about: `I'm Zaki Pedio, an Italian security professional and independent researcher who focuses on red-team techniques and offensive security. Security isn't just my job, it's how I think: I spend my time hunting for weaknesses, building exploits, and designing RF and hardware prototypes that turn theory into testable proof-of-concepts. I started competing in CTFs and, at 16, reached Top-100 on HackTheBox globally; those contests taught me how to solve messy, multi-disciplinary problems fast.\n\nProfessionally I work on red-team operations and web application pentesting, and I'm steadily expanding my experience in exploit development, radio-frequency research, hardware-focused testing and embedded devices. I'm hands-on: I experiment with microcontroller prototypes and use my 3D printer to make enclosures and early prototypes so ideas become testable proofs.\n\nMy long-term goal is to found or lead a defence-focused company that delivers offensive-informed solutions to real organisations. If you like complicated problems, practical proof-of-concepts and solutions that stand up to real-world adversaries, we'll get along.`,
      projects: [
          {
            "name": "AssemblyWebServer",
            "desc": "Minimal web server written in x86-64 assembly",
            "tags": ["assembly", "x86-64", "webserver", "low-level"],
            "url": "https://github.com/ZakiPedio/AssemblyWebServer"
          },
          {
            "name": "C2Watch",
            "desc": "Threat Intelligence framework to monitor C2 in the wild",
            "tags": ["threat-intel", "C2", "monitoring", "framework"],
            "url": "https://github.com/ZakiPedio/C2Watch"
          },
          {
            "name": "RRReporter",
            "desc": "Simple semi-automatic reporter for bug bounty or other bug-related report",
            "tags": ["bug-bounty", "reporting", "automation", "tool"],
            "url": "https://github.com/ZakiPedio/RRReporter"
          },
          {
            "name": "HelloWorld-in-Brainfuck",
            "desc": "Simple HelloWorld in Brainfuck",
            "tags": ["brainfuck", "esolang", "example"],
            "url": "https://github.com/ZakiPedio/HelloWorld-in-Brainfuck"
          }
      ],
      articles: [
          {
            "title": "WannaCry: The Malware That Brought the World to Its Knees",
            "desc": "A deep dive into the global ransomware attack that paralyzed hospitals, businesses, and governments worldwide",
            "tags": ["ransomware", "malware-analysis", "global-threat"],
            "url": "https://blog.zakipedio.dev/malware-analysis/wannacry-the-malware-that-brought-the-world-to-its-knees"
          },
          {
            "title": "LockBit 3.0: Ransomware as... a Service?",
            "desc": "Exploring the RaaS business model and technical evolution of one of the most prolific ransomware families",
            "tags": ["ransomware", "RaaS", "threat-analysis"],
            "url": "https://blog.zakipedio.dev/malware-analysis/lockbit-3.0-ransomware-as...-a-service"
          },
          {
            "title": "Remcos in the Shadows: A Fileless Multi-Stage Attack Dissected",
            "desc": "Analyzing the sophisticated multi-stage delivery and evasion techniques of the Remcos RAT",
            "tags": ["RAT", "malware-analysis", "evasion-techniques"],
            "url": "https://blog.zakipedio.dev/malware-analysis/remcos-in-the-shadows-a-fileless-multi-stage-attack-dissected"
          },
          {
            "title": "Unmasking Cobalt Strike: A Shodan-Powered Hunt",
            "desc": "Leveraging Shodan and network intelligence to identify and track Cobalt Strike C2 infrastructure",
            "tags": ["C2", "threat-hunting", "shodan"],
            "url": "https://blog.zakipedio.dev/command-and-control/unmasking-cobalt-strike-a-shodan-powered-hunt"
          }
      ]
      // NOTE: removed client-side secretNote to avoid accidental leak
    };

    // -- storage keys --
    const HISTORY_KEY = 't_history_v2';
    let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    let hpos = history.length;

    // -- helper renderers --
    function println(html, cls=''){
      const node = document.createElement('div');
      node.className = 'out ' + cls;
      node.innerHTML = html;
      output.appendChild(node);
      window.scrollTo(0, document.body.scrollHeight);
    }

    function echo(text){ println(`<span class="muted">haxxor@laptop:~$</span> ${escapeHtml(text)}`); }
    function escapeHtml(s){ return (s+'').replace(/[&<>\"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

    // -- formatted outputs: table & badges --
    function projectsTable(list){
      // attribute-safe escaping (relies on your escapeHtml for &,<,>)
      const escapeAttr = s => escapeHtml(String(s)).replace(/"/g, '&quot;');

      // only allow http(s) and mailto links to avoid "javascript:" injections
      const isSafeUrl = u => typeof u === 'string' && (/^https?:\/\//i.test(u) || /^mailto:/i.test(u));

      const rows = (list || []).map(p => {
        const nameHtml = escapeHtml(p.name || '');
        const descHtml = escapeHtml(p.desc || '');
        const tagsHtml = (p.tags || []).map(t => `<span class="badge">${escapeHtml(t)}</span>`).join(' ');

        const nameWithLink = (p.url && isSafeUrl(p.url))
          ? `<a href="${escapeAttr(p.url)}" target="_blank" rel="noopener noreferrer">${nameHtml}</a>`
          : nameHtml;

        return `<tr>
          <td><b>${nameWithLink}</b><div class="muted small">${descHtml}</div></td>
          <td style="text-align:right">${tagsHtml}</td>
        </tr>`;
      }).join('');

      return `<table class="table">${rows}</table>`;
    }

    function articlesTable(list){
      // attribute-safe escaping (relies on your escapeHtml for &,<,>)
      const escapeAttr = s => escapeHtml(String(s)).replace(/"/g, '&quot;');

      // only allow http(s) and mailto links to avoid "javascript:" injections
      const isSafeUrl = u => typeof u === 'string' && (/^https?:\/\//i.test(u) || /^mailto:/i.test(u));

      const rows = (list || []).map(a => {
        const titleHtml = escapeHtml(a.title || '');
        const descHtml = escapeHtml(a.desc || '');
        const tagsHtml = (a.tags || []).map(t => `<span class="badge">${escapeHtml(t)}</span>`).join(' ');

        const titleWithLink = (a.url && isSafeUrl(a.url))
          ? `<a href="${escapeAttr(a.url)}" target="_blank" rel="noopener noreferrer">${titleHtml}</a>`
          : titleHtml;

        return `<tr>
          <td><b>${titleWithLink}</b><div class="muted small">${descHtml}</div></td>
          <td style="text-align:right">${tagsHtml}</td>
        </tr>`;
      }).join('');

      return `<table class="table">${rows}</table>`;
    }

    // -- boot + ascii art
    const ASCII = `       _                        
       \\*-.                    
        )  _\`-.                 
       .  : \`. .                
       : _   '  \\               
       ; *\` _.   \`*-._          
       \`-.-'          \`-.       
         ;       \`       \`.     
         :.       .        \\    
         . \\  .   :   .-'   .   
         '  \`+.;  ;  '      :   
         :  '  |    ;       ;-. 
         ; '   : :\`-:     _.\\* ;
[bug] .*' /  .*' ; .*\`- +'  \\*' 
      \`*-\*   \`*-\*  \`*-\*'`;

    const introBoot = [
      'POWER: ON',
      'INITIALIZING SUBSYSTEMS...',
      'CHECK: STORAGE... OK',
      'CHECK: NETWORK... minimal',
      'LOADING PROFILE: haxxor@laptop',
    ];

    let bootIndex = 0;
    let bootCancelled = false;

    function playBoot(){
      output.innerHTML='';
      bootIndex = 0; bootCancelled = false;
      typeLines(introBoot, ()=>{
        // ascii art fade-in
        const pre = document.createElement('pre'); pre.className='ascii out'; pre.textContent = ASCII;
        output.appendChild(pre);
        setTimeout(()=>{
          println('<div class="muted">Type "help"</div>');
        }, 350);
      });
    }

    function typeLines(lines, cb){
      if(bootCancelled){ cb(); return; }
      if(bootIndex>=lines.length){ cb(); return; }
      const line = lines[bootIndex++];
      let i=0; const node = document.createElement('div'); node.className='out'; output.appendChild(node);
      function step(){
        node.textContent = line.slice(0,i++);
        window.scrollTo(0,document.body.scrollHeight);
        if(i<=line.length) setTimeout(step, 10 + Math.random()*10);
        else setTimeout(()=>typeLines(lines,cb), 50);
      }
      step();
    }

    // allow Esc to skip boot
    document.addEventListener('keydown', e=>{ if(e.key==='Escape') bootCancelled = true; });

    // --------------------------
    //  Client-side decryptor
    // --------------------------
    // This implements the PBKDF2 -> AES-GCM logic. It expects a public
    // encrypted.json in the same directory with the structure:
    // {
    //   "kdf": "pbkdf2",
    //   "kdf_params": { "salt_b64": "...", "iterations": 200000 },
    //   "iv_b64": "...",
    //   "ct_b64": "..."   // ciphertext + tag, base64
    // }
    //
    // Generate encrypted.json using the encrypt.py helper (recommended).
    //
    const CRYPTO = {
      encryptedMeta: null
    };

    function b64ToArrayBuffer(b64) {
      // atob -> binary string -> Uint8Array
      const binary = atob(b64);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    async function deriveKeyPBKDF2(passphrase, salt_b64, iterations) {
      const enc = new TextEncoder();
      const pwKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), {name:'PBKDF2'}, false, ['deriveKey']);
      const salt = new Uint8Array(b64ToArrayBuffer(salt_b64));
      const key = await crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt, iterations, hash: 'SHA-256'},
        pwKey,
        {name: 'AES-GCM', length: 256},
        false,
        ['decrypt']
      );
      return key;
    }

    async function decryptWithPassphrase(passphrase) {
      if (!CRYPTO.encryptedMeta) throw new Error('encrypted payload not loaded');
      const meta = CRYPTO.encryptedMeta;
      if (meta.kdf !== 'pbkdf2') throw new Error('unsupported kdf: ' + meta.kdf);
      const salt_b64 = meta.kdf_params.salt_b64;
      const iterations = meta.kdf_params.iterations;
      const iv_b64 = meta.iv_b64;
      const ct_b64 = meta.ct_b64;

      const key = await deriveKeyPBKDF2(passphrase, salt_b64, iterations);
      const iv = new Uint8Array(b64ToArrayBuffer(iv_b64));
      const ct = b64ToArrayBuffer(ct_b64);

      try {
        const plainBuf = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, key, ct);
        const decoder = new TextDecoder();
        return decoder.decode(plainBuf);
      } catch (e) {
        // decryption failed (bad passphrase / wrong key / tampered)
        throw new Error('decryption failed (likely wrong passphrase)');
      }
    }

    async function loadEncryptedMeta() {
      // attempt to fetch encrypted.json non-cached; ignore failure gracefully
      try {
        const r = await fetch('encrypted.json', {cache: 'no-store'});
        if (!r.ok) {
          console.debug('encrypted.json not present or fetch failed:', r.status);
          CRYPTO.encryptedMeta = null;
          return;
        }
        CRYPTO.encryptedMeta = await r.json();
        console.debug('encrypted.json loaded');
      } catch (e) {
        console.debug('failed to load encrypted.json', e);
        CRYPTO.encryptedMeta = null;
      }
    }

    // --------------------------
    //  commands
    // --------------------------
    function help(){
      println('<b>available commands</b><br>'+
        '<div class="muted">help</div> - show this message<br>'+
        '<div class="muted">about</div> - short bio<br>'+
        '<div class="muted">projects</div> - list my public projects<br>'+
        '<div class="muted">articles</div> - list my blog articles<br>'+
        //'<div class="muted">cv</div> - download CV (if provided)<br>'+ // now i dont want to add it, maybe later
        '<div class="muted">hallOfFame</div> - certification i have and competition i won<br>'+
        '<div class="muted">contact</div> - ways to reach me<br>'+
        '<div class="muted">secret</div> - can you answer correctly?<br>'+
        '<div class="muted">clear</div> - clear the screen'
      );
    }

    function about(){ println(escapeHtml(STATE.about)); }

    function projects(){ println(projectsTable(STATE.projects)); }

    function articles(){ println(articlesTable(STATE.articles)); }

    function cv(){ println('<span class="muted">no CV uploaded. add a cvUrl in the source.</span>'); }

    function contact(){ println(`Find me on <a href="https://www.linkedin.com/in/zakipedio/" target="_blank" rel="noopener">LinkedIn</a>`); }

    // NEW secretFlow: derives key client-side and attempts to decrypt public encrypted.json
    async function secretFlow(){
      // quick UX: indicate we're attempting
      println('<span class="muted">secret flow: preparing...</span>');

      // ensure encrypted payload is loaded (try again if not)
      if (!CRYPTO.encryptedMeta) {
        await loadEncryptedMeta();
      }

      // if encrypted payload still missing, tell user
      if (!CRYPTO.encryptedMeta) {
        println('<span class="muted">secret not configured on server (encrypted.json missing)</span>');
        return;
      }

      // prompt for passphrase like your supplied implementation
      const pass = prompt('Greatest OS ever? (case-sensitive)');
      if (!pass) { println('<span class="muted">access aborted</span>'); return; }

      // attempt decrypt and print result or failure
      println('<span class="muted">deriving key and attempting decrypt...</span>');
      try {
        const plaintext = await decryptWithPassphrase(pass);
        println(`<b>Secret unlocked</b><br><span class="muted">${escapeHtml(plaintext)}</span>`);
      } catch (e) {
        println('<span class="muted">invalid token or decryption failed</span>');
        console.debug(e);
      }
    }

    function hallOfFame(){
      println('<b>Certifications and Competitions</b><br>' +
      '<div class="muted">- Maldev Academy "The Malware Development Course"</div>' +
      '<div class="muted">- Top 100 in HackTheBox Globally</div>' +
      '<div class="muted">- OliCyber.IT Finals Participant</div>' +
      '<div class="muted">- CyberChallenge.IT Finals Participant (x2)</div>' +
      '<div class="muted">- Cisco CCNA Certified</div>' +
      '<div class="muted">- Cisco IT Essentials Certified</div>'+ 
      '<div class="muted">- Cambridge English B2 Certified</div>');
    }

    // command dispatcher
    function handleCommand(raw){
      const cmd = (raw || '').trim();
      if(!cmd) return;
      history.push(cmd); localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); hpos = history.length;
      echo(cmd);
      const [c, ...args] = cmd.split(/\s+/);
      switch((c||'').toLowerCase()){
        case 'help': help(); break;
        case 'about': about(); break;
        case 'projects': projects(); break;
        case 'articles': articles(); break;
        //case 'cv': cv(); break; // now i dont want to add it, maybe later
        case 'halloffame': hallOfFame(); break;
        case 'contact': contact(); break;
        case 'clear': output.innerHTML=''; break;
        case 'secret': secretFlow(); break;
        default:
          println(`<span class="muted">command not found:</span> ${escapeHtml(c)} — type <code>help</code>`);
      }
    }

    form.addEventListener('submit', e=>{ e.preventDefault(); handleCommand(input.value); input.value=''; });

    input.addEventListener('keydown', e=>{
      if(e.key==='ArrowUp'){ if(hpos>0) hpos--; input.value = history[hpos]||''; e.preventDefault(); }
      if(e.key==='ArrowDown'){ if(hpos<history.length) hpos++; input.value = history[hpos]||''; e.preventDefault(); }
      if(e.ctrlKey && e.key.toLowerCase()==='k'){ e.preventDefault(); input.focus(); }
      if(e.key==='Tab'){ e.preventDefault(); // simple autocomplete for commands
        const v = input.value.trim().toLowerCase(); const cmds=['help','about','projects','articles','hallOfFame','contact','secret','clear']; // remove 'cv'
        const match = cmds.find(x=>x.startsWith(v)); if(match) input.value = match; }
    });

    // keyboard shortcut: ctrl+k focuses input
    document.addEventListener('keydown', e=>{ if(e.ctrlKey && e.key.toLowerCase()==='k'){ e.preventDefault(); input.focus(); } });

    // start
    // attempt to pre-load the encrypted.json so secret is ready when asked
    loadEncryptedMeta().catch(()=>{/* ignore */});
    playBoot();

  }); // DOMContentLoaded
})(); // IIFE
