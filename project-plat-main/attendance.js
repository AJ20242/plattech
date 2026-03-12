const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const userBadge = document.getElementById('userBadge');
const attendanceMsg = document.getElementById('attendanceMsg');
const attendanceForm = document.getElementById('attendanceForm');
const attendanceDate = document.getElementById('attendanceDate');
const attendanceStatus = document.getElementById('attendanceStatus');
const attendanceSubmitBtn = document.getElementById('attendanceSubmitBtn');
const totalStudentsEl = document.getElementById('totalStudents');
const presentCountEl = document.getElementById('presentCount');
const lateCountEl = document.getElementById('lateCount');
const absentCountEl = document.getElementById('absentCount');
const recordsList = document.getElementById('recordsList');

let role = "";


/* =========================
   ROLE UI CONTROL
========================= */

function configureAttendanceUI(role){

  if(role === "student"){
    attendanceStatus.innerHTML = `
      <option value="present">Present</option>
    `;
  }

  if(role === "professor"){
    attendanceStatus.innerHTML = `
      <option value="late">Late</option>
      <option value="absent">Absent</option>
    `;
  }

}


/* =========================
   THEME
========================= */

function getPreferredTheme(){
  const saved = localStorage.getItem(THEME_KEY);
  if(saved === "light" || saved === "dark") return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? "dark" : "light";
}

function applyTheme(theme){
  document.documentElement.setAttribute('data-theme', theme);
}

function todayIso(){
  return new Date().toISOString().slice(0,10);
}


/* =========================
   API
========================= */

async function getCurrentUser(){
  const response = await fetch('/api/auth/me',{credentials:'same-origin'});
  if(!response.ok) return null;
  return response.json();
}

async function markAttendance(payload){

  const response = await fetch('/api/attendance/mark',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    credentials:'same-origin',
    body:JSON.stringify(payload)
  });

  const data = await response.json().catch(()=>({message:'Unexpected server response'}));

  if(!response.ok){
    throw new Error(data.detail || data.message || "Failed to save attendance");
  }

  return data;
}


async function getAttendanceToday(date){

  const response = await fetch(`/api/attendance/today?date=${date}`,{
    credentials:'same-origin'
  });

  const data = await response.json().catch(()=>({}));

  if(!response.ok){
    throw new Error(data.detail || data.message || "Failed to load attendance");
  }

  return data;
}


/* =========================
   RENDER
========================= */

function renderSummary(summary){

  totalStudentsEl.textContent = summary.totalStudents ?? 0;
  presentCountEl.textContent = summary.present ?? 0;
  lateCountEl.textContent = summary.late ?? 0;
  absentCountEl.textContent = summary.absent ?? 0;

}


function renderRecords(records){

  if(!records || records.length === 0){
    recordsList.innerHTML = `<article class="record-item">No attendance records.</article>`;
    return;
  }

  recordsList.innerHTML = records.map(r => `
    <article class="record-item">
      <h3>${r.fullName}</h3>
      <p>${r.userEmail}</p>
      <span class="status-badge">${r.status}</span>
    </article>
  `).join("");

}


/* =========================
   LOAD DATA
========================= */

async function refreshAttendance(){

  const data = await getAttendanceToday(attendanceDate.value);

  renderSummary(data.summary || {});
  renderRecords(data.records || []);

}


/* =========================
   ROLE PERMISSIONS
========================= */

function updateUiByRole(user){

  role = String(user.role || "student").toLowerCase();

  userBadge.textContent = `Signed in as ${user.email} (${user.role})`;

  configureAttendanceUI(role);


  /* STUDENT */

  if(role === "student"){

    attendanceSubmitBtn.disabled = false;
    attendanceMsg.textContent = "Student mode: mark yourself PRESENT.";

    return;
  }


  /* PROFESSOR */

  if(role === "professor"){

    attendanceSubmitBtn.disabled = false;
    attendanceMsg.textContent = "Professor mode: mark students LATE or ABSENT.";

    return;
  }


  /* ADMIN */

  attendanceForm.style.display = "none";

  attendanceMsg.textContent = "Admins cannot access attendance.";

}



/* =========================
   EVENTS
========================= */

attendanceForm.addEventListener('submit', async (e)=>{

  e.preventDefault();

  attendanceSubmitBtn.disabled = true;
  attendanceSubmitBtn.textContent = "Saving...";

  try{

    const result = await markAttendance({
      date:attendanceDate.value,
      status:attendanceStatus.value
    });

    attendanceMsg.textContent = result.message || "Attendance saved.";

    await refreshAttendance();

  }
  catch(err){
    attendanceMsg.textContent = err.message;
  }

  attendanceSubmitBtn.disabled = false;
  attendanceSubmitBtn.textContent = "Save Attendance";

});


attendanceDate.addEventListener('change', async ()=>{
  await refreshAttendance();
});


logoutBtn.addEventListener('click', async ()=>{
  await fetch('/api/auth/logout',{method:'POST',credentials:'same-origin'});
  window.location.href = "index.html";
});


themeToggle.addEventListener('click',()=>{

  const current = document.documentElement.getAttribute('data-theme') || "light";
  const next = current === "dark" ? "light" : "dark";

  applyTheme(next);
  localStorage.setItem(THEME_KEY,next);

});


/* =========================
   INIT
========================= */

(async()=>{

  applyTheme(getPreferredTheme());

  attendanceDate.value = todayIso();

  const user = await getCurrentUser();

  if(!user){
    window.location.href = "index.html";
    return;
  }

  updateUiByRole(user);

  await refreshAttendance();

})();