# Fight Club - React Edition with JSON Database

A full-stack Fight Club management system built with **React** frontend and **Express** backend using **JSON file database** (lowdb).

## 🚀 Features

- ✅ **React Frontend** - Modern, component-based UI
- ✅ **JSON Database** - No MongoDB required! Uses lowdb for file-based storage
- ✅ **JWT Authentication** - Secure token-based auth
- ✅ **Real-time Updates** - Live fight and chat updates
- ✅ **Admin Panel** - Full management controls
- ✅ **Rank System** - 20 progressive ranks with XP
- ✅ **Fight Disputes** - Handle when both claim victory
- ✅ **Leaderboard** - Rankings by wins
- ✅ **Dark Theme** - Gritty underground aesthetic

## 📁 Project Structure

```
fight-club-react/
├── server.js              # Express backend with JSON DB
├── db.json               # JSON database file (auto-created)
├── package.json          # Backend dependencies
├── .env                  # Environment variables
├── uploads/              # Avatar uploads folder
└── client/               # React frontend
    ├── src/
    │   ├── App.js       # Main React app with all components
    │   ├── index.js     # React entry point
    │   └── index.css    # Tailwind styles
    ├── public/
    │   └── index.html   # HTML template
    ├── package.json     # Frontend dependencies
    └── tailwind.config.js
```

## 🛠️ Installation

### Prerequisites
- Node.js (v14 or higher)
- npm

### Step 1: Install Backend Dependencies
```bash
cd fight-club-react
npm install
```

### Step 2: Install Frontend Dependencies
```bash
cd client
npm install
cd ..
```

## ▶️ Running the Application

### Option 1: Development Mode (Recommended)

**Terminal 1 - Backend:**
```bash
npm start
# Server runs on http://localhost:3000
```

**Terminal 2 - Frontend:**
```bash
cd client
npm start
# React app runs on http://localhost:3001
```

### Option 2: Production Build

```bash
# Build React frontend
cd client
npm run build
cd ..

# Serve from Express
npm start
```

## 🎮 Usage

### First Time Setup

1. **Start both backend and frontend**
2. **Visit** `http://localhost:3001` (or 3000 if production)
3. **Register** with username "admin" to get admin privileges
4. **Create** additional test users
5. **Start fighting!**

### User Flow

1. **Login/Register** → Create fighter profile
2. **Dashboard** → Issue challenges to opponents
3. **Accept Fights** → Respond to incoming challenges
4. **Claim Victory** → After fight, click "I WON"
5. **Admin Reviews** → Admin approves or resolves disputes
6. **Rank Up** → Gain XP and unlock new ranks

## 📊 Database Structure (db.json)

The JSON database automatically creates and maintains:

```json
{
  "users": [
    {
      "id": "uuid",
      "username": "fighter1",
      "password": "pass123",
      "name": "Iron Mike",
      "role": "user",
      "hp": 50,
      "xp": 150,
      "rank": "Novice",
      "rankLevel": 2,
      "wins": 3,
      "losses": 1,
      "gifts": ["Bandage", "Tape", "Cotton Gloves"],
      "avatar": "/uploads/123456.jpg",
      "style": "Boxing",
      "bio": "The best there is"
    }
  ],
  "fights": [
    {
      "id": "uuid",
      "p1": "user-id-1",
      "p2": "user-id-2",
      "status": "completed",
      "winnerClaimId": "user-id-1",
      "proposedDate": "2024-01-20T10:00:00Z"
    }
  ],
  "chats": [],
  "ranks": [
    { "id": 1, "name": "Rookie", "xpRequired": 0, "gifts": [...] }
  ],
  "xpConfig": {
    "winXP": 50,
    "lossXP": 10,
    "drawXP": 20
  }
}
```

## 🔑 API Endpoints

### Authentication
- `POST /api/register` - Create new user
- `POST /api/login` - Login user
- `GET /api/me` - Get current user

### Users
- `GET /api/users` - Get all users
- `PUT /api/me` - Update profile
- `PUT /api/admin/user/:id` - Admin update user
- `DELETE /api/admin/user/:id` - Admin delete user

### Fights
- `POST /api/fights` - Create fight challenge
- `GET /api/fights` - Get all fights
- `PUT /api/fights/:id` - Update fight status
- `PUT /api/fights/:id/selectwinner` - Admin select winner
- `DELETE /api/fights/:id` - Admin delete fight

### Ranks
- `GET /api/ranks` - Get all ranks
- `PUT /api/ranks/:id` - Admin update rank

### Chat
- `POST /api/chat` - Send message
- `GET /api/chat` - Get messages

### Upload
- `POST /api/upload` - Upload avatar image

## 🎨 Tech Stack

**Frontend:**
- React 18
- React Router v6
- Axios
- React Toastify
- Tailwind CSS
- Font Awesome

**Backend:**
- Express.js
- lowdb (JSON database)
- JWT (jsonwebtoken)
- Multer (file uploads)
- CORS

## 🔐 Default Credentials

Create your own users! Username "admin" automatically gets admin role.

## 🎯 Key Features Explained

### 1. JSON Database (lowdb)
- **No MongoDB needed!**
- Stores everything in `db.json` file
- Auto-saves on every change
- Perfect for development and small deployments

### 2. Fight Dispute System
When both fighters claim victory:
- Status changes to "DISPUTED" (orange)
- Admin sees both claims
- Admin selects actual winner
- Stats updated accordingly

### 3. XP & Rank System
- 20 progressive ranks (Rookie → God of War)
- Auto rank-up when XP threshold reached
- Each rank unlocks unique gifts
- Admin can customize XP requirements

### 4. Admin Controls
- Approve fight results
- Resolve disputes
- Edit user stats (HP, XP, Rank)
- Delete users
- Modify rank system
- Full database access

## 📝 Environment Variables

Create `.env` file:
```
PORT=3000
JWT_SECRET=your_secret_key_here
NODE_ENV=development
```

## 🚨 Important Notes

- **Database file** (`db.json`) is created automatically on first run
- **Uploads folder** is created automatically for avatars
- **Passwords** are stored in plain text (use bcrypt in production!)
- **CORS** is enabled for development (configure for production)

## 🔄 Migration from MongoDB Version

This React + JSON version has the **same features** as the MongoDB version:
- All routes maintained
- Same API structure
- Compatible frontend logic
- Just swap the database layer!

## 🐛 Troubleshooting

**Port already in use:**
```bash
# Change PORT in .env
PORT=3001
```

**Database not saving:**
- Check file permissions on `db.json`
- Ensure write access to project folder

**Frontend can't connect:**
- Verify backend is running on port 3000
- Check proxy setting in client/package.json

## 📦 Production Deployment

### Build Frontend
```bash
cd client
npm run build
```

### Serve Static Files
Update server.js:
```javascript
app.use(express.static(path.join(__dirname, 'client/build')));
```

### Deploy to Heroku/Vercel/Railway
- Set environment variables
- Ensure db.json has write permissions
- Configure build commands

## 🤝 Contributing

1. Fork the repo
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## 📄 License

MIT License - Feel free to use for any project!

## 🎮 Happy Fighting!

Built with ❤️ and ⚔️
