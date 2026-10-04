# TaskFlow – Task Management Application
Stack: HTML/CSS/JS frontend · Node.js + Express backend · SQLite database · JWT auth

## Run
    npm install
    npm start
Open http://localhost:3000

## Features
- Register / login (bcrypt-hashed passwords, JWT sessions)
- Authorization: users see/edit only their own tasks; first registered user is Admin and can see all tasks
- CRUD on tasks (title, description, priority, status, due date)
- Search, filter, status counters, overdue highlighting
- Responsive for desktop and mobile

## API
POST /api/register · POST /api/login · GET/POST /api/tasks · PUT/DELETE /api/tasks/:id
