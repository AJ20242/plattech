// ai-questions.js

function loadAIQuestions(){

    const container = document.getElementById("aiQuestions");
    
    if(!container) return;
    
    const page = window.location.pathname.toLowerCase();
    
    let questions = [];
    
    if(page.includes("dashboard")){
    
    questions = [
    ["Check Attendance","How do I check my attendance?"],
    ["My Quizzes","Where can I see my quizzes?"],
    ["Materials","What materials are available?"],
    ["Submit Activity","How do I submit activities?"],
    ["Create Ticket","How do I create a support ticket?"]
    ];
    
    }
    
    else if(page.includes("material")){
    
    questions = [
    ["Create Materials","How do I create materials?"],
    ["Mark Attendance","How do I mark attendance?"],
    ["Create Quiz","How do I create quizzes?"],
    ["Create Exam","How do I create exams?"],
    ["Manage Activities","How do I manage student activities?"]
    ];
    
    }
    
    else if(page.includes("admin")){
    
    questions = [
    ["Manage Users","How do I manage users?"],
    ["Change Roles","How do I change user roles?"],
    ["Support Tickets","How do I review support tickets?"],
    ["Audit Logs","How do I check audit logs?"],
    ["Audit System","What does the blockchain audit system do?"]
    ];
    
    }
    
    questions.forEach(q => {
    
    const btn = document.createElement("a");
    
    btn.className = "feature-question-btn";
    
    btn.href = "chat.html?q=" + encodeURIComponent(q[1]);
    
    btn.textContent = q[0];
    
    container.appendChild(btn);
    
    });
    
    }
    
    document.addEventListener("DOMContentLoaded", loadAIQuestions);