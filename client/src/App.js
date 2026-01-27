import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, Link } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import axios from 'axios';

const API_BASE = 'https://fight-club-eny5.onrender.com';

const api = axios.create({
  baseURL: `${API_BASE}/api`, // full backend endpoint
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('fc_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auth Context
const AuthContext = React.createContext();

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('fc_token');
    if (token) {
      api.get('/me')
        .then(res => {
          setUser(res.data);
          setLoading(false);
        })
        .catch(() => {
          localStorage.removeItem('fc_token');
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    const res = await api.post('/login', { username, password });
    localStorage.setItem('fc_token', res.data.token);
    setUser(res.data.user);
    return res.data;
  };

  const register = async (username, password, name) => {
    await api.post('/register', { username, password, name });
  };

  const logout = () => {
    localStorage.removeItem('fc_token');
    setUser(null);
  };

  const updateUser = (userData) => {
    setUser(userData);
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, updateUser, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

function useAuth() {
  return React.useContext(AuthContext);
}

// Navbar Component
function Navbar() {
  const { user, logout } = useAuth();

  if (!user) return null;

  return (
    <nav className="bg-[#121212] border-b border-[#333333] p-4 sticky top-0 z-40 shadow-lg">
      <div className="container mx-auto flex justify-between items-center">
        <div className="flex items-center space-x-3 cursor-pointer group">
          <div className="relative">
            <i className="fa-solid fa-chess-knight text-[#dc2626] text-3xl group-hover:rotate-12 transition-transform duration-300"></i>
          </div>
          <div>
            <Link to="/dashboard" className="font-['Black_Ops_One'] text-3xl text-white tracking-wider">
              FIGHT <span className="text-[#dc2626]">Arena</span>
            </Link>
          </div>
        </div>
        <div className="flex space-x-6 text-lg font-bold items-center">
          <Link to="/dashboard" className="hover:text-[#dc2626] transition">DASHBOARD</Link>
          <Link to="/fighters" className="hover:text-purple-400 transition">FIGHTERS</Link>
          <Link to="/rankings" className="hover:text-[#dc2626] transition">RANKINGS</Link>
          <Link to="/ranks" className="hover:text-[#eab308] transition">RANKS</Link>
          <Link to="/profile" className="hover:text-blue-400 transition">PROFILE</Link>
          {user.role === 'admin' && (
            <Link to="/admin" className="text-[#eab308] hover:text-yellow-400 transition">ADMIN</Link>
          )}
          <button
            onClick={logout}
            className="text-[#dc2626] border border-[#dc2626] px-3 py-1 rounded hover:bg-[#dc2626] hover:text-white transition"
          >
            LOGOUT
          </button>
        </div>
      </div>
    </nav>
  );
}

// Landing Page Component
function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-[#050505] text-white overflow-hidden">
      {/* Animated Background */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-red-950/20 to-black"></div>
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-600/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-red-800/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
      </div>

      {/* Content */}
      <div className="relative z-10">
        {/* Hero Section */}
        <div className="container mx-auto px-6 pt-20 pb-32">
          <div className="text-center max-w-4xl mx-auto">
            {/* Logo */}
            <div className="mb-8 animate-fade-in">
              <i className="fa-solid fa-hand-point-up text-[#dc2626] text-8xl mb-6 inline-block animate-pulse"></i>
              <h1 className="font-['Black_Ops_One'] text-7xl md:text-9xl tracking-wider mb-4 text-center leading-tight">
                <span className="block">RGMA</span>
                <span className="block">
                  FIGHT <span className="block text-[#dc2626]">ARENA</span>
                </span>
              </h1>
            </div>

            {/* Tagline */}
            <div className="mb-12 space-y-4">
              <p className="text-3xl md:text-4xl font-bold text-white">
                The First Rule of Fight Arena...
              </p>
              <p className="text-xl md:text-2xl text-gray-300">
                You <span className="text-[#dc2626] font-bold">DO</span> fear none but Allah.
              </p>
              <p className="text-gray-500 max-w-2xl mx-auto mt-6">
                Welcome to Fight Arena, where you can Challenge opponents, climb ranks,
                unlock achievements, and become the Supreme Champion.
              </p>
            </div>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row gap-6 justify-center mb-16">
              <button
                onClick={() => navigate('/register')}
                className="bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['Black_Ops_One'] text-xl px-12 py-4 rounded-lg uppercase tracking-widest transition-all shadow-[0_0_30px_rgba(220,38,38,0.5)] hover:shadow-[0_0_50px_rgba(220,38,38,0.8)] transform hover:scale-105"
              >
                <i className="fa-solid fa-hand-fist mr-3"></i>
                Join the Arena
              </button>
              <button
                onClick={() => navigate('/login')}
                className="bg-transparent border-2 border-white hover:bg-white hover:text-black text-white font-bold text-xl px-12 py-4 rounded-lg uppercase tracking-widest transition-all transform hover:scale-105"
              >
                <i className="fa-solid fa-right-to-bracket mr-3"></i>
                Enter Arena
              </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-8 max-w-3xl mx-auto">
              <div className="text-center">
                <p className="text-5xl font-['Black_Ops_One'] text-[#dc2626] mb-2">20</p>
                <p className="text-sm text-gray-400 uppercase tracking-wider">Ranks to Conquer</p>
              </div>
              <div className="text-center">
                <p className="text-5xl font-['Black_Ops_One'] text-[#eab308] mb-2">∞</p>
                <p className="text-sm text-gray-400 uppercase tracking-wider">Battles to Fight</p>
              </div>
              <div className="text-center">
                <p className="text-5xl font-['Black_Ops_One'] text-blue-500 mb-2">1</p>
                <p className="text-sm text-gray-400 uppercase tracking-wider">Champion</p>
              </div>
            </div>
          </div>
        </div>

        {/* Features Section */}
        <div className="bg-black/50 backdrop-blur-sm py-20 border-y border-red-900/30">
          <div className="container mx-auto px-6">
            <h2 className="font-['Black_Ops_One'] text-4xl md:text-5xl text-center mb-16">
              WHAT AWAITS <span className="text-[#dc2626]">YOU</span>
            </h2>

            <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
              {/* Feature 1 */}
              <div className="bg-[#1e1e1e] border border-[#333333] p-6 rounded-lg hover:border-[#dc2626] transition group">
                <div className="text-5xl mb-4 text-[#dc2626] group-hover:scale-110 transition">
                  <i className="fa-solid fa-fire"></i>
                </div>
                <h3 className="font-['Black_Ops_One'] text-xl mb-3">Epic Battles</h3>
                <p className="text-gray-400 text-sm">
                  Challenge fighters, accept duels, and claim victory. Every fight brings you closer to glory.
                </p>
              </div>

              {/* Feature 2 */}
              <div className="bg-[#1e1e1e] border border-[#333333] p-6 rounded-lg hover:border-[#eab308] transition group">
                <div className="text-5xl mb-4 text-[#eab308] group-hover:scale-110 transition">
                  <i className="fa-solid fa-trophy"></i>
                </div>
                <h3 className="font-['Black_Ops_One'] text-xl mb-3">20 Ranks</h3>
                <p className="text-gray-400 text-sm">
                  Rise from Rookie to Supreme Champion. Unlock exclusive gifts and rewards at each rank.
                </p>
              </div>

              {/* Feature 3 */}
              <div className="bg-[#1e1e1e] border border-[#333333] p-6 rounded-lg hover:border-blue-500 transition group">
                <div className="text-5xl mb-4 text-blue-500 group-hover:scale-110 transition">
                  <i className="fa-solid fa-user-gear"></i>
                </div>
                <h3 className="font-['Black_Ops_One'] text-xl mb-3">Deep Profiles</h3>
                <p className="text-gray-400 text-sm">
                  Customize your fighter with stats, achievements, social links, and personal story.
                </p>
              </div>

              {/* Feature 4 */}
              <div className="bg-[#1e1e1e] border border-[#333333] p-6 rounded-lg hover:border-purple-500 transition group">
                <div className="text-5xl mb-4 text-purple-500 group-hover:scale-110 transition">
                  <i className="fa-solid fa-users"></i>
                </div>
                <h3 className="font-['Black_Ops_One'] text-xl mb-3">Fighter Directory</h3>
                <p className="text-gray-400 text-sm">
                  Browse all fighters, view detailed profiles, and issue challenges with one click.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Ranks Preview Section */}
        <div className="py-20">
          <div className="container mx-auto px-6">
            <h2 className="font-['Black_Ops_One'] text-4xl md:text-5xl text-center mb-4">
              CLIMB THE <span className="text-[#eab308]">LADDER</span>
            </h2>
            <p className="text-gray-400 text-center mb-12 max-w-2xl mx-auto">
              Start as a Rookie and fight your way to become the Supreme Champion.
              Each rank unlocks unique gifts and brings you closer to immortality.
            </p>

            <div className="flex justify-center items-center gap-4 flex-wrap max-w-4xl mx-auto">
              <div className="bg-gradient-to-br from-gray-800 to-gray-900 px-4 py-2 rounded border border-gray-700">
                <p className="text-gray-400 text-sm">Rookie</p>
              </div>
              <i className="fa-solid fa-arrow-right text-gray-600"></i>
              <div className="bg-gradient-to-br from-blue-900 to-blue-950 px-4 py-2 rounded border border-blue-700">
                <p className="text-blue-400 text-sm">Vanguard</p>
              </div>
              <i className="fa-solid fa-arrow-right text-gray-600"></i>
              <div className="bg-gradient-to-br from-purple-900 to-purple-950 px-4 py-2 rounded border border-purple-700">
                <p className="text-purple-400 text-sm">Ruthless</p>
              </div>
              <i className="fa-solid fa-arrow-right text-gray-600"></i>
              <div className="bg-gradient-to-br from-yellow-900 to-yellow-950 px-4 py-2 rounded border border-yellow-600 shadow-[0_0_20px_rgba(234,179,8,0.3)]">
                <p className="text-[#eab308] text-sm font-bold">Supreme Champion</p>
              </div>
            </div>

            <div className="text-center mt-12">
              <p className="text-gray-500 text-sm mb-4">22,000 XP • 40 Unlocked Gifts • Unlimited Glory</p>
            </div>
          </div>
        </div>


        {/* Final CTA */}
        <div className="py-20">
          <div className="container mx-auto px-6 text-center">
            <h2 className="font-['Black_Ops_One'] text-4xl md:text-6xl mb-6">
              READY TO <span className="text-[#dc2626]">FIGHT</span>?
            </h2>
            <p className="text-xl text-gray-400 mb-8 max-w-2xl mx-auto">
              Create your profile,
              challenge opponents, and become a legend.
            </p>
            <button
              onClick={() => navigate('/register')}
              className="bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['Black_Ops_One'] text-2xl px-16 py-5 rounded-lg uppercase tracking-widest transition-all shadow-[0_0_40px_rgba(220,38,38,0.6)] hover:shadow-[0_0_60px_rgba(220,38,38,0.9)] transform hover:scale-110 animate-pulse"
            >
              Start Your Journey
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-gray-800 py-8 bg-black">
          <div className="container mx-auto px-6 text-center text-gray-600 text-sm">
            <p>© 2026 Fight Arena • All Rights Reserved •</p>
            <p className="mt-2">
              <span className="text-[#dc2626]">●</span> Contact : No NEed
              <span className="mx-4">•</span>
              <span className="text-[#eab308]">●</span> Email: aneone5555@gmail.com
              <span className="mx-4">•</span>
              <span className="text-blue-500">●</span> Just Fight
            </p>
          </div>
        </div>
      </div>

      <style>{`
        @keyframes fade-in {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .animate-fade-in {
          animation: fade-in 1s ease-out;
        }

        .delay-1000 {
          animation-delay: 1s;
        }
      `}</style>
    </div>
  );
}

// Login Component
function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(username, password);
      toast.success('Welcome back!');
      navigate('/dashboard'); // FIXED: replaced window.location.href
    } catch (err) {
      toast.error(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (

    <div className="min-h-screen flex items-center justify-center bg-[#000000]">
      <div className="max-w-md w-full bg-[#1e1e1e] p-8 border border-[#333333] rounded shadow-2xl">
        <h2 className="font-['Black_Ops_One'] text-4xl text-center mb-2 text-white">
          ARENA <span className="text-[#dc2626]">ACCESS</span>
        </h2>
        <p className="text-center text-gray-500 text-xs mb-8 uppercase tracking-widest">Identify Yourself</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 uppercase font-bold">Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-red-500 outline-none transition"
              placeholder="Enter username"
              required
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 uppercase font-bold">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-red-500 outline-none transition"
              placeholder="Enter password"
              required
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['Black_Ops_One'] py-3 rounded uppercase tracking-widest transition-all shadow-[0_0_15px_rgba(220,38,38,0.4)]"
          >
            {loading ? 'Loading...' : 'Enter Arena'}
          </button>
        </form>
        <p className="mt-6 text-center text-sm text-gray-500">
          New recruit? <Link to="/register" className="text-[#dc2626] hover:underline">Create Fighter Profile</Link>
        </p>
      </div>
    </div>
  );
}

// Register Component
function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await register(username, password, name);
      toast.success('Registration complete! Please login.');
      navigate('/login'); // FIXED: replaced window.location.href
    } catch (err) {
      toast.error(err.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050505]">
      <div className="max-w-md w-full bg-[#1e1e1e] p-8 border border-[#333333] rounded shadow-2xl">
        <h2 className="font-['Black_Ops_One'] text-3xl text-center mb-6 text-white">RECRUITMENT</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-[#eab308] outline-none"
            placeholder="Username"
            required
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-[#eab308] outline-none"
            placeholder="Password"
            required
          />
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-[#eab308] outline-none"
            placeholder="Fighter Name"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gray-800 hover:bg-gray-700 text-white font-bold py-3 rounded border border-gray-600 transition"
          >
            {loading ? 'Loading...' : 'JOIN THE Arena'}
          </button>
        </form>
        <p className="mt-4 text-center">
          <Link to="/login" className="text-gray-500 hover:text-white text-sm">Back to Login</Link>
        </p>
      </div>
    </div>
  );
}

// Fighter Card Component
function FighterCard({ fighter, currentUser, onChallenge }) {
  const [showDetails, setShowDetails] = useState(false);

  const isCurrentUser = fighter.id === currentUser.id;
  const stats = fighter.statistics || {};

  return (
    <div className="bg-[#1e1e1e] border border-[#333333] rounded-lg overflow-hidden hover:border-purple-500 transition group">
      {/* Header */}
      <div className="p-4 bg-gradient-to-r from-black to-gray-900 flex items-center gap-4">
        <img
          src={fighter.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(fighter.name)}&background=dc2626&color=fff`}
          className="w-20 h-20 rounded-full border-4 border-[#dc2626] object-cover"
          alt={fighter.name}
        />
        <div className="flex-grow">
          <h3 className="font-['Black_Ops_One'] text-2xl text-white">{fighter.name}</h3>
          <div className="flex gap-2 mt-1">
            <span className="text-xs bg-red-900/30 text-red-400 border border-red-900 px-2 py-1 rounded uppercase font-bold">
              {fighter.rank}
            </span>
            <span className="text-xs bg-green-900/30 text-green-400 border border-green-900 px-2 py-1 rounded uppercase font-bold">
              HP: {fighter.hp}%
            </span>
            <span className="text-xs bg-blue-900/30 text-blue-400 border border-blue-900 px-2 py-1 rounded uppercase font-bold">
              XP: {fighter.xp}
            </span>
          </div>
        </div>
        {!isCurrentUser && (
          <button
            onClick={() => onChallenge(fighter)}
            className="bg-[#dc2626] hover:bg-[#b91c1c] text-white px-4 py-2 rounded font-bold uppercase text-sm transition shadow-[0_0_10px_rgba(220,38,38,0.3)]"
          >
            <i className="fa-solid fa-hand-fist mr-2"></i>
            Challenge
          </button>
        )}
        {isCurrentUser && (
          <span className="bg-purple-900/30 text-purple-400 border border-purple-900 px-3 py-2 rounded text-xs font-bold uppercase">
            <i className="fa-solid fa-user mr-1"></i> You
          </span>
        )}
      </div>

      {/* Stats Bar */}
      <div className="px-4 py-3 bg-black border-t border-gray-800 grid grid-cols-3 gap-4 text-center">
        <div>
          <p className="text-xs text-gray-500 uppercase">Record</p>
          <p className="text-sm font-bold">
            <span className="text-green-500">{fighter.wins}W</span>
            <span className="text-gray-600 mx-1">-</span>
            <span className="text-red-500">{fighter.losses}L</span>
          </p>
        </div>
        <div>
          <p className="text-xs text-gray-500 uppercase">Style</p>
          <p className="text-sm font-bold text-white">{fighter.style || 'Unknown'}</p>
        </div>
        <div>
          <p className="text-xs text-gray-500 uppercase">Streak</p>
          <p className="text-sm font-bold text-yellow-500">{stats.winStreak || 0}</p>
        </div>
      </div>

      {/* Quick Info */}
      <div className="px-4 py-3 border-t border-gray-800">
        {fighter.location && (
          <p className="text-xs text-gray-400 mb-1">
            <i className="fa-solid fa-location-dot text-red-500 mr-2"></i>
            {fighter.location}
          </p>
        )}
        {fighter.motto && (
          <p className="text-xs text-gray-300 italic">"{fighter.motto}"</p>
        )}
        {fighter.bio && (
          <p className="text-xs text-gray-400 mt-2 line-clamp-2">{fighter.bio}</p>
        )}
      </div>

      {/* Toggle Details */}
      <div className="px-4 py-2 border-t border-gray-800">
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="w-full text-xs text-purple-400 hover:text-purple-300 font-bold uppercase transition"
        >
          {showDetails ? '▲ Hide Details' : '▼ View Full Profile'}
        </button>
      </div>

      {/* Expanded Details */}
      {showDetails && (
        <div className="px-4 py-4 bg-black border-t border-gray-800 space-y-4">
          {/* Physical Stats */}
          {(fighter.weight || fighter.height || fighter.reach || fighter.stance) && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-dumbbell text-blue-500 mr-2"></i>
                Physical Stats
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {fighter.weight && <p><span className="text-gray-500">Weight:</span> <span className="text-white">{fighter.weight}</span></p>}
                {fighter.height && <p><span className="text-gray-500">Height:</span> <span className="text-white">{fighter.height}</span></p>}
                {fighter.reach && <p><span className="text-gray-500">Reach:</span> <span className="text-white">{fighter.reach}</span></p>}
                {fighter.stance && <p><span className="text-gray-500">Stance:</span> <span className="text-white">{fighter.stance}</span></p>}
              </div>
            </div>
          )}

          {/* Background */}
          {fighter.background && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-book text-yellow-500 mr-2"></i>
                Background
              </h4>
              <p className="text-xs text-gray-300">{fighter.background}</p>
            </div>
          )}

          {/* Training */}
          {(fighter.trainingSchedule || fighter.favoriteMove) && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-fire text-orange-500 mr-2"></i>
                Training
              </h4>
              {fighter.trainingSchedule && (
                <p className="text-xs text-gray-400 mb-1">
                  <span className="text-gray-500">Schedule:</span> {fighter.trainingSchedule}
                </p>
              )}
              {fighter.favoriteMove && (
                <p className="text-xs text-gray-400">
                  <span className="text-gray-500">Signature Move:</span> <span className="text-red-400 font-bold">{fighter.favoriteMove}</span>
                </p>
              )}
            </div>
          )}

          {/* Advanced Stats */}
          {(stats.knockouts || stats.submissions || stats.decisions) > 0 && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-chart-line text-green-500 mr-2"></i>
                Fight Statistics
              </h4>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="bg-gray-900 p-2 rounded">
                  <p className="text-red-500 font-bold text-lg">{stats.knockouts || 0}</p>
                  <p className="text-[10px] text-gray-500 uppercase">KO</p>
                </div>
                <div className="bg-gray-900 p-2 rounded">
                  <p className="text-blue-500 font-bold text-lg">{stats.submissions || 0}</p>
                  <p className="text-[10px] text-gray-500 uppercase">SUB</p>
                </div>
                <div className="bg-gray-900 p-2 rounded">
                  <p className="text-green-500 font-bold text-lg">{stats.decisions || 0}</p>
                  <p className="text-[10px] text-gray-500 uppercase">DEC</p>
                </div>
              </div>
            </div>
          )}

          {/* Achievements */}
          {fighter.achievements && fighter.achievements.length > 0 && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-trophy text-yellow-500 mr-2"></i>
                Achievements
              </h4>
              <div className="flex flex-wrap gap-1">
                {fighter.achievements.map((achievement, idx) => (
                  <span key={idx} className="text-[10px] bg-gray-900 text-yellow-400 px-2 py-1 rounded border border-yellow-900">
                    <i className="fa-solid fa-star mr-1"></i>{achievement}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Social Links */}
          {fighter.socialLinks && (fighter.socialLinks.twitter || fighter.socialLinks.instagram || fighter.socialLinks.youtube) && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-share-nodes text-purple-500 mr-2"></i>
                Social Media
              </h4>
              <div className="flex gap-3">
                {fighter.socialLinks.twitter && (
                  <a href={`https://twitter.com/${fighter.socialLinks.twitter}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300 text-sm">
                    <i className="fa-brands fa-twitter mr-1"></i>{fighter.socialLinks.twitter}
                  </a>
                )}
                {fighter.socialLinks.instagram && (
                  <a href={`https://instagram.com/${fighter.socialLinks.instagram}`} target="_blank" rel="noopener noreferrer" className="text-pink-400 hover:text-pink-300 text-sm">
                    <i className="fa-brands fa-instagram mr-1"></i>{fighter.socialLinks.instagram}
                  </a>
                )}
                {fighter.socialLinks.youtube && (
                  <a href={`https://youtube.com/${fighter.socialLinks.youtube}`} target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 text-sm">
                    <i className="fa-brands fa-youtube mr-1"></i>{fighter.socialLinks.youtube}
                  </a>
                )}
              </div>
            </div>
          )}

          {/* Gifts */}
          {fighter.gifts && fighter.gifts.length > 0 && (
            <div>
              <h4 className="text-xs text-gray-500 uppercase font-bold mb-2">
                <i className="fa-solid fa-gift text-red-500 mr-2"></i>
                Unlocked Gifts ({fighter.gifts.length})
              </h4>
              <div className="flex flex-wrap gap-1">
                {fighter.gifts.slice(0, 10).map((gift, idx) => (
                  <span key={idx} className="text-[10px] bg-gray-900 text-gray-300 px-2 py-1 rounded border border-gray-700">
                    {gift}
                  </span>
                ))}
                {fighter.gifts.length > 10 && (
                  <span className="text-[10px] bg-gray-900 text-gray-500 px-2 py-1 rounded border border-gray-700">
                    +{fighter.gifts.length - 10} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Fighters Directory Page
function Fighters() {
  const { user } = useAuth();
  const [fighters, setFighters] = useState([]);
  const [filteredFighters, setFilteredFighters] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRank, setFilterRank] = useState('all');
  const [sortBy, setSortBy] = useState('wins');
  const [showChallengeModal, setShowChallengeModal] = useState(false);
  const [selectedFighter, setSelectedFighter] = useState(null);
  const [fightDate, setFightDate] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFighters();
  }, []);

  useEffect(() => {
    filterAndSortFighters();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fighters, searchTerm, filterRank, sortBy]);

  const loadFighters = async () => {
    try {
      const res = await api.get('/users');
      setFighters(res.data.filter(f => f.role !== 'admin'));
      setLoading(false);
    } catch (err) {
      toast.error('Failed to load fighters');
      setLoading(false);
    }
  };

  const filterAndSortFighters = () => {
    let filtered = [...fighters];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(f =>
        f.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.style.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.location?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Rank filter
    if (filterRank !== 'all') {
      filtered = filtered.filter(f => f.rank === filterRank);
    }

    // Sort
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'wins':
          return b.wins - a.wins;
        case 'xp':
          return b.xp - a.xp;
        case 'rank':
          return b.rankLevel - a.rankLevel;
        case 'name':
          return a.name.localeCompare(b.name);
        default:
          return 0;
      }
    });

    setFilteredFighters(filtered);
  };

  const handleChallenge = (fighter) => {
    setSelectedFighter(fighter);
    setShowChallengeModal(true);
  };

  const sendChallenge = async () => {
    if (!fightDate) {
      toast.error('Please select a fight date');
      return;
    }

    try {
      await api.post('/fights', {
        p1: user.id,
        p2: selectedFighter.id,
        proposedDate: fightDate
      });
      toast.success(`Challenge sent to ${selectedFighter.name}!`);
      setShowChallengeModal(false);
      setFightDate('');
      setSelectedFighter(null);
    } catch (err) {
      toast.error('Failed to send challenge');
    }
  };

  const uniqueRanks = [...new Set(fighters.map(f => f.rank))].sort();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] text-white">
        <Navbar />
        <div className="container mx-auto p-6 text-center">
          <p className="text-2xl">Loading fighters...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6">
        {/* Header */}
        <div className="mb-6">
          <h1 className="font-['Black_Ops_One'] text-5xl mb-2">
            FIGHTER <span className="text-purple-500">DIRECTORY</span>
          </h1>
          <p className="text-gray-500 text-sm">Browse all fighters and issue challenges</p>
        </div>

        {/* Filters */}
        <div className="bg-[#1e1e1e] border border-[#333333] rounded-lg p-4 mb-6">
          <div className="grid md:grid-cols-4 gap-4">
            {/* Search */}
            <div>
              <label className="text-xs text-gray-400 uppercase font-bold mb-1 block">Search</label>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Name, style, location..."
                className="w-full bg-black border border-gray-700 text-white p-2 rounded outline-none focus:border-purple-500"
              />
            </div>

            {/* Rank Filter */}
            <div>
              <label className="text-xs text-gray-400 uppercase font-bold mb-1 block">Rank</label>
              <select
                value={filterRank}
                onChange={(e) => setFilterRank(e.target.value)}
                className="w-full bg-black border border-gray-700 text-white p-2 rounded outline-none focus:border-purple-500"
              >
                <option value="all">All Ranks</option>
                {uniqueRanks.map(rank => (
                  <option key={rank} value={rank}>{rank}</option>
                ))}
              </select>
            </div>

            {/* Sort By */}
            <div>
              <label className="text-xs text-gray-400 uppercase font-bold mb-1 block">Sort By</label>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="w-full bg-black border border-gray-700 text-white p-2 rounded outline-none focus:border-purple-500"
              >
                <option value="wins">Most Wins</option>
                <option value="xp">Highest XP</option>
                <option value="rank">Highest Rank</option>
                <option value="name">Name (A-Z)</option>
              </select>
            </div>

            {/* Stats */}
            <div className="flex items-end">
              <div className="text-sm">
                <p className="text-gray-400">Showing <span className="text-purple-500 font-bold">{filteredFighters.length}</span> of <span className="text-white font-bold">{fighters.length}</span> fighters</p>
              </div>
            </div>
          </div>
        </div>

        {/* Fighter Cards Grid */}
        {filteredFighters.length > 0 ? (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredFighters.map(fighter => (
              <FighterCard
                key={fighter.id}
                fighter={fighter}
                currentUser={user}
                onChallenge={handleChallenge}
              />
            ))}
          </div>
        ) : (
          <div className="bg-[#1e1e1e] border border-[#333333] rounded-lg p-12 text-center">
            <i className="fa-solid fa-user-slash text-6xl text-gray-700 mb-4"></i>
            <p className="text-xl text-gray-500">No fighters found</p>
            <p className="text-sm text-gray-600 mt-2">Try adjusting your filters</p>
          </div>
        )}
      </div>

      {/* Challenge Modal */}
      {showChallengeModal && selectedFighter && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-[#1e1e1e] border border-purple-500 rounded-lg p-6 max-w-md w-full shadow-[0_0_30px_rgba(168,85,247,0.3)]">
            <h3 className="font-['Black_Ops_One'] text-2xl mb-4">
              CHALLENGE <span className="text-purple-500">{selectedFighter.name}</span>
            </h3>

            {/* Fighter Info */}
            <div className="bg-black p-4 rounded-lg mb-4 flex items-center gap-4">
              <img
                src={selectedFighter.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(selectedFighter.name)}&background=dc2626&color=fff`}
                className="w-16 h-16 rounded-full border-2 border-purple-500"
                alt={selectedFighter.name}
              />
              <div>
                <p className="text-white font-bold text-lg">{selectedFighter.name}</p>
                <p className="text-sm text-gray-400">{selectedFighter.rank} • {selectedFighter.wins}W-{selectedFighter.losses}L</p>
              </div>
            </div>

            {/* Date Picker */}
            <div className="mb-4">
              <label className="text-xs text-gray-400 uppercase font-bold mb-2 block">
                <i className="fa-solid fa-calendar mr-2"></i>
                Fight Date & Time
              </label>
              <input
                type="datetime-local"
                value={fightDate}
                onChange={(e) => setFightDate(e.target.value)}
                className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-purple-500 outline-none"
                required
              />
            </div>

            {/* Buttons */}
            <div className="flex gap-3">
              <button
                onClick={sendChallenge}
                disabled={!fightDate}
                className="flex-1 bg-[#dc2626] hover:bg-[#b91c1c] disabled:bg-gray-700 text-white font-bold py-3 rounded uppercase transition"
              >
                <i className="fa-solid fa-hand-fist mr-2"></i>
                Send Challenge
              </button>
              <button
                onClick={() => {
                  setShowChallengeModal(false);
                  setFightDate('');
                  setSelectedFighter(null);
                }}
                className="px-6 bg-gray-800 hover:bg-gray-700 text-white font-bold py-3 rounded uppercase transition"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Dashboard Component
function Dashboard() {
  const { user, updateUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [fights, setFights] = useState([]);
  const [opponent, setOpponent] = useState('');
  const [fightDate, setFightDate] = useState('');

  const loadData = async () => {
    try {
      const [meRes, usersRes, fightsRes] = await Promise.all([
        api.get('/me'),
        api.get('/users'),
        api.get('/fights')
      ]);
      updateUser(meRes.data);
      setUsers(usersRes.data);
      setFights(fightsRes.data);
    } catch (err) {
      toast.error('Failed to load data');
    }
  };

  useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sendChallenge = async (e) => {
    e.preventDefault();
    if (!opponent) {
      toast.error('Select an opponent');
      return;
    }
    try {
      await api.post('/fights', {
        p1: user.id,
        p2: opponent,
        proposedDate: fightDate
      });
      toast.success('Challenge sent!');
      loadData();
      setOpponent('');
      setFightDate('');
    } catch (err) {
      toast.error('Failed to send challenge');
    }
  };

  const acceptFight = async (fightId) => {
    try {
      await api.put(`/fights/${fightId}`, { status: 'accepted' });
      toast.success('Fight accepted!');
      loadData();
    } catch (err) {
      toast.error('Failed to accept fight');
    }
  };

  const claimVictory = async (fightId) => {
    try {
      await api.put(`/fights/${fightId}`, {
        status: 'review',
        winnerClaimId: user.id
      });
      toast.info('Victory claim submitted for review');
      loadData();
    } catch (err) {
      toast.error('Failed to submit claim');
    }
  };

  const myFights = fights.filter(f => f.p1?.id === user.id || f.p2?.id === user.id);
  const incoming = myFights.filter(f => f.status === 'pending' && f.p2?.id === user.id);
  const active = myFights.filter(f => ['accepted', 'review', 'disputed'].includes(f.status));

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6 space-y-6">
        {/* Profile Header */}
        <div className="bg-[#1e1e1e] border border-[#333333] p-6 rounded-lg flex items-center gap-6">
          <img
            src={user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name)}&background=dc2626&color=fff`}
            className="w-28 h-28 rounded-full border-4 border-[#dc2626] object-cover"
            alt="Avatar"
          />
          <div className="flex-grow">
            <h2 className="font-['Black_Ops_One'] text-5xl uppercase">{user.name}</h2>
            <div className="flex gap-3 mt-2">
              <span className="text-[#dc2626] font-bold text-sm uppercase border border-red-900 bg-red-900/20 px-2 py-1 rounded">
                {user.rank}
              </span>
              <span className="text-green-500 font-bold text-sm uppercase border border-green-900 bg-green-900/20 px-2 py-1 rounded">
                HP: {user.hp}%
              </span>
              <span className="text-blue-400 font-bold text-sm uppercase border border-blue-900 bg-blue-900/20 px-2 py-1 rounded">
                XP: {user.xp}
              </span>
            </div>
            <div className="mt-4 text-sm">
              RECORD: <span className="font-bold">{user.wins}W - {user.losses}L</span>
            </div>
          </div>
          <Link
            to="/profile"
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded font-bold transition"
          >
            EDIT PROFILE
          </Link>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Challenge Form */}
          <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#333333]">
            <h3 className="font-['Black_Ops_One'] text-xl mb-4">
              <i className="fa-solid fa-hand-fist text-[#dc2626]"></i> ISSUE CHALLENGE
            </h3>
            <form onSubmit={sendChallenge} className="space-y-3">
              <select
                value={opponent}
                onChange={(e) => setOpponent(e.target.value)}
                className="w-full bg-black border border-gray-700 text-white p-3 rounded outline-none"
              >
                <option value="">-- Choose Fighter --</option>
                {users.filter(u => u.id !== user.id).map(u => (
                  <option key={u.id} value={u.id}>{u.name} ({u.rank})</option>
                ))}
              </select>
              <input
                type="datetime-local"
                value={fightDate}
                onChange={(e) => setFightDate(e.target.value)}
                className="w-full bg-black border border-gray-700 text-white p-3 rounded outline-none"
                required
              />
              <button
                type="submit"
                className="w-full bg-[#dc2626] hover:bg-[#b91c1c] text-white font-bold py-3 rounded transition"
              >
                SEND CHALLENGE
              </button>
            </form>
            <p className="text-center mt-3 text-sm text-gray-500">
              Or <Link to="/fighters" className="text-purple-400 hover:underline">browse all fighters</Link>
            </p>
          </div>

          {/* Incoming Challenges */}
          <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#333333]">
            <h3 className="font-['Black_Ops_One'] text-xl text-[#dc2626] mb-4">
              <i className="fa-solid fa-bell"></i> INCOMING CHALLENGES
            </h3>
            <div className="space-y-2 max-h-[200px] overflow-y-auto">
              {incoming.length ? incoming.map(f => (
                <div key={f.id} className="bg-black p-3 rounded border-l-4 border-yellow-500 flex justify-between items-center">
                  <div>
                    <p className="text-white font-bold text-sm">{f.p1?.name}</p>
                    <p className="text-xs text-gray-500">{new Date(f.proposedDate).toLocaleString()}</p>
                  </div>
                  <button
                    onClick={() => acceptFight(f.id)}
                    className="bg-green-600 hover:bg-green-500 text-white px-3 py-1 rounded text-xs font-bold transition"
                  >
                    ACCEPT
                  </button>
                </div>
              )) : <p className="text-gray-600 italic text-sm text-center py-4">No pending challenges</p>}
            </div>
          </div>
        </div>

        {/* Active Fights */}
        <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#333333]">
          <h3 className="font-['Black_Ops_One'] text-xl text-green-500 mb-4">
            <i className="fa-solid fa-fire"></i> ACTIVE BOUTS
          </h3>
          <div className="space-y-3">
            {active.length ? active.map(f => {
              const opponent = f.p1?.id === user.id ? f.p2 : f.p1;
              const canClaim = f.status === 'accepted';
              const isDisputed = f.status === 'disputed';

              return (
                <div key={f.id} className={`bg-black p-4 rounded flex justify-between items-center border ${isDisputed ? 'border-orange-500' : 'border-gray-800'}`}>
                  <div className="flex items-center gap-4">
                    <div className={`h-10 w-1 ${isDisputed ? 'bg-orange-500' : 'bg-[#dc2626]'}`}></div>
                    <div>
                      <p className="text-white font-bold text-lg">VS {opponent?.name}</p>
                      <p className="text-xs text-gray-500 uppercase">
                        Status: <span className={f.status === 'review' ? 'text-yellow-500' : isDisputed ? 'text-orange-500' : 'text-green-500'}>{f.status}</span>
                      </p>
                    </div>
                  </div>
                  <div>
                    {canClaim && (
                      <button
                        onClick={() => claimVictory(f.id)}
                        className="bg-[#dc2626] hover:bg-red-700 text-white text-xs px-4 py-2 rounded font-bold uppercase transition"
                      >
                        I WON
                      </button>
                    )}
                    {f.status === 'review' && (
                      <span className="text-yellow-500 text-xs border border-yellow-500 px-3 py-2 rounded bg-yellow-900/10 font-bold">
                        <i className="fa-solid fa-gavel"></i> UNDER REVIEW
                      </span>
                    )}
                    {isDisputed && (
                      <span className="text-orange-500 text-xs border border-orange-500 px-3 py-2 rounded bg-orange-900/10 font-bold">
                        <i className="fa-solid fa-scale-balanced"></i> DISPUTED
                      </span>
                    )}
                  </div>
                </div>
              );
            }) : <p className="text-gray-600 italic text-center py-8">No active fights. Go challenge someone!</p>}
          </div>
        </div>
      </div>
    </div>
  );
}

// Profile Component
function Profile() {
  const { user, updateUser } = useAuth();
  const [formData, setFormData] = useState({
    name: '',
    style: '',
    bio: '',
    location: '',
    weight: '',
    height: '',
    reach: '',
    stance: 'Orthodox',
    background: '',
    trainingSchedule: '',
    favoriteMove: '',
    motto: '',
    socialLinks: { twitter: '', instagram: '', youtube: '' },
    achievements: []
  });
  const [newAchievement, setNewAchievement] = useState('');
  const [uploading, setUploading] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (user) {
      setFormData({
        name: user.name || '',
        style: user.style || '',
        bio: user.bio || '',
        location: user.location || '',
        weight: user.weight || '',
        height: user.height || '',
        reach: user.reach || '',
        stance: user.stance || 'Orthodox',
        background: user.background || '',
        trainingSchedule: user.trainingSchedule || '',
        favoriteMove: user.favoriteMove || '',
        motto: user.motto || '',
        socialLinks: user.socialLinks || { twitter: '', instagram: '', youtube: '' },
        achievements: user.achievements || []
      });
    }
  }, [user]);

  const handleChange = (e) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleSocialChange = (platform, value) => {
    setFormData(prev => ({
      ...prev,
      socialLinks: { ...prev.socialLinks, [platform]: value }
    }));
  };

  const addAchievement = () => {
    if (newAchievement.trim() && formData.achievements.length < 20) {
      setFormData(prev => ({
        ...prev,
        achievements: [...prev.achievements, newAchievement.trim()]
      }));
      setNewAchievement('');
    }
  };

  const removeAchievement = (index) => {
    setFormData(prev => ({
      ...prev,
      achievements: prev.achievements.filter((_, i) => i !== index)
    }));
  };

  const handleAvatarUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    const formDataUpload = new FormData();
    formDataUpload.append('file', file);

    try {
      const res = await api.post('/upload', formDataUpload);
      await api.put('/me', { avatar: res.data.filePath });
      const meRes = await api.get('/me');
      updateUser(meRes.data);
      toast.success('Avatar updated!');
    } catch (err) {
      toast.error('Failed to upload avatar');
    } finally {
      setUploading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);

    try {
      await api.put('/me', formData);
      const meRes = await api.get('/me');
      updateUser(meRes.data);
      toast.success('Profile updated successfully!');
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update profile');
    } finally {
      setSaving(false);
    }
  };

  if (!user) return <Navigate to="/login" />;

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6">
        <div className="max-w-4xl mx-auto bg-[#1e1e1e] border border-[#333333] rounded-lg p-6">
          <h2 className="font-['Black_Ops_One'] text-3xl mb-6">
            EDIT <span className="text-blue-400">PROFILE</span>
          </h2>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Avatar Upload */}
            <div className="flex items-center gap-6 pb-6 border-b border-gray-800">
              <img
                src={user.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.name)}&background=dc2626&color=fff`}
                className="w-24 h-24 rounded-full border-4 border-[#dc2626] object-cover"
                alt="Avatar"
              />
              <div>
                <label className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded font-bold cursor-pointer transition">
                  {uploading ? 'Uploading...' : 'Change Avatar'}
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleAvatarUpload}
                    disabled={uploading}
                    className="hidden"
                  />
                </label>
                <p className="text-xs text-gray-500 mt-2">JPG, PNG, GIF (Max 2MB)</p>
              </div>
            </div>

            {/* Basic Info */}
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-gray-400 uppercase font-bold">Fighter Name</label>
                <input
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                  placeholder="Your fighter name"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 uppercase font-bold">Fighting Style</label>
                <input
                  name="style"
                  value={formData.style}
                  onChange={handleChange}
                  className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                  placeholder="e.g., Boxing, MMA, Muay Thai"
                />
              </div>
            </div>

            {/* Bio */}
            <div>
              <label className="text-xs text-gray-400 uppercase font-bold">Bio</label>
              <textarea
                name="bio"
                value={formData.bio}
                onChange={handleChange}
                rows="3"
                maxLength="500"
                className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none resize-none"
                placeholder="Brief bio about yourself..."
              />
              <p className="text-xs text-gray-600 mt-1">{formData.bio.length}/500</p>
            </div>

            {/* Physical Stats */}
            <div>
              <h3 className="text-lg font-bold text-blue-400 mb-3">
                <i className="fa-solid fa-dumbbell"></i> Physical Stats
              </h3>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Location</label>
                  <input
                    name="location"
                    value={formData.location}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="City, Country"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Weight</label>
                  <input
                    name="weight"
                    value={formData.weight}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="e.g., 185 lbs"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Height</label>
                  <input
                    name="height"
                    value={formData.height}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="e.g., 6 feet 2 inches"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Reach</label>
                  <input
                    name="reach"
                    value={formData.reach}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="e.g., 76 inches"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-gray-400 uppercase font-bold">Stance</label>
                  <select
                    name="stance"
                    value={formData.stance}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                  >
                    <option value="Orthodox">Orthodox</option>
                    <option value="Southpaw">Southpaw</option>
                    <option value="Switch">Switch</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Background Story */}
            <div>
              <h3 className="text-lg font-bold text-blue-400 mb-3">
                <i className="fa-solid fa-book"></i> Background & Training
              </h3>
              <div className="space-y-4">
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Background Story</label>
                  <textarea
                    name="background"
                    value={formData.background}
                    onChange={handleChange}
                    rows="4"
                    maxLength="1000"
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none resize-none"
                    placeholder="Your fighting journey, how you started..."
                  />
                  <p className="text-xs text-gray-600 mt-1">{formData.background.length}/1000</p>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Training Schedule</label>
                  <textarea
                    name="trainingSchedule"
                    value={formData.trainingSchedule}
                    onChange={handleChange}
                    rows="2"
                    maxLength="500"
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none resize-none"
                    placeholder="e.g., Mon-Fri 6AM-8AM, Sat 9AM-12PM"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Favorite Move</label>
                  <input
                    name="favoriteMove"
                    value={formData.favoriteMove}
                    onChange={handleChange}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="Your signature move"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">Personal Motto</label>
                  <input
                    name="motto"
                    value={formData.motto}
                    onChange={handleChange}
                    maxLength="200"
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="Your fighting philosophy"
                  />
                </div>
              </div>
            </div>

            {/* Social Links */}
            <div>
              <h3 className="text-lg font-bold text-blue-400 mb-3">
                <i className="fa-solid fa-share-nodes"></i> Social Media
              </h3>
              <div className="grid md:grid-cols-3 gap-4">
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">
                    <i className="fa-brands fa-twitter text-blue-400"></i> Twitter
                  </label>
                  <input
                    value={formData.socialLinks.twitter}
                    onChange={(e) => handleSocialChange('twitter', e.target.value)}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="@username"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">
                    <i className="fa-brands fa-instagram text-pink-500"></i> Instagram
                  </label>
                  <input
                    value={formData.socialLinks.instagram}
                    onChange={(e) => handleSocialChange('instagram', e.target.value)}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="@username"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-bold">
                    <i className="fa-brands fa-youtube text-red-600"></i> YouTube
                  </label>
                  <input
                    value={formData.socialLinks.youtube}
                    onChange={(e) => handleSocialChange('youtube', e.target.value)}
                    className="w-full bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="Channel name"
                  />
                </div>
              </div>
            </div>

            {/* Achievements */}
            <div>
              <h3 className="text-lg font-bold text-blue-400 mb-3">
                <i className="fa-solid fa-trophy"></i> Achievements
              </h3>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <input
                    value={newAchievement}
                    onChange={(e) => setNewAchievement(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addAchievement())}
                    className="flex-1 bg-black border border-gray-700 text-white p-3 rounded focus:border-blue-500 outline-none"
                    placeholder="Add an achievement..."
                    maxLength="100"
                  />
                  <button
                    type="button"
                    onClick={addAchievement}
                    disabled={!newAchievement.trim() || formData.achievements.length >= 20}
                    className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white px-4 py-2 rounded font-bold transition"
                  >
                    ADD
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {formData.achievements.map((achievement, idx) => (
                    <span key={idx} className="bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center gap-2">
                      <i className="fa-solid fa-star text-yellow-500"></i>
                      {achievement}
                      <button
                        type="button"
                        onClick={() => removeAchievement(idx)}
                        className="text-red-500 hover:text-red-400 ml-1"
                      >
                        ✕
                      </button>
                    </span>
                  ))}
                </div>
                <p className="text-xs text-gray-600">{formData.achievements.length}/20 achievements</p>
              </div>
            </div>

            {/* Submit Button */}
            <div className="flex gap-4 pt-4 border-t border-gray-800">
              <button
                type="submit"
                disabled={saving}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 text-white font-['Black_Ops_One'] py-3 rounded uppercase tracking-widest transition-all shadow-[0_0_15px_rgba(59,130,246,0.4)]"
              >
                {saving ? 'SAVING...' : 'SAVE PROFILE'}
              </button>
              <Link
                to="/dashboard"
                className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded transition text-center"
              >
                CANCEL
              </Link>
            </div>
          </form>

          {/* Statistics Display (Read-only) */}
          {user.statistics && (
            <div className="mt-6 pt-6 border-t border-gray-800">
              <h3 className="text-lg font-bold text-[#eab308] mb-3">
                <i className="fa-solid fa-chart-line"></i> Fighting Statistics
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Knockouts</p>
                  <p className="text-2xl font-bold text-[#dc2626]">{user.statistics.knockouts || 0}</p>
                </div>
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Submissions</p>
                  <p className="text-2xl font-bold text-blue-500">{user.statistics.submissions || 0}</p>
                </div>
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Decisions</p>
                  <p className="text-2xl font-bold text-green-500">{user.statistics.decisions || 0}</p>
                </div>
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Total Fights</p>
                  <p className="text-2xl font-bold text-white">{user.statistics.totalFights || 0}</p>
                </div>
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Win Streak</p>
                  <p className="text-2xl font-bold text-[#eab308]">{user.statistics.winStreak || 0}</p>
                </div>
                <div className="bg-black p-4 rounded border border-gray-800 text-center">
                  <p className="text-gray-400 text-xs uppercase">Best Streak</p>
                  <p className="text-2xl font-bold text-purple-500">{user.statistics.bestWinStreak || 0}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Rankings Component
function Rankings() {
  const [users, setUsers] = useState([]);

  useEffect(() => {
    api.get('/users').then(res => {
      const sorted = res.data.filter(u => u.role !== 'admin').sort((a, b) => b.wins - a.wins);
      setUsers(sorted);
    });
  }, []);

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6">
        <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#333333]">
          <h2 className="font-['Black_Ops_One'] text-4xl mb-8">LEADERBOARD</h2>
          <table className="w-full text-left">
            <thead className="bg-black text-gray-400 text-xs uppercase">
              <tr>
                <th className="p-4">Rank</th>
                <th className="p-4">Fighter</th>
                <th className="p-4">Class</th>
                <th className="p-4">Record</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {users.map((u, i) => (
                <tr key={u.id} className="hover:bg-gray-800/50 transition">
                  <td className={`p-4 font-bold text-xl ${i === 0 ? 'text-[#eab308]' : i === 1 ? 'text-gray-300' : i === 2 ? 'text-orange-700' : 'text-gray-500'}`}>
                    #{i + 1}
                  </td>
                  <td className="p-4 flex items-center gap-4">
                    <img
                      src={u.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(u.name)}&background=333&color=fff`}
                      className="w-12 h-12 rounded-full border border-gray-700"
                      alt={u.name}
                    />
                    <span className="font-bold text-lg">{u.name}</span>
                  </td>
                  <td className="p-4 text-gray-400 text-sm uppercase">{u.rank}</td>
                  <td className="p-4 font-bold text-lg">
                    <span className="text-white">{u.wins}</span>
                    <span className="text-gray-600 mx-1">-</span>
                    <span className="text-gray-500">{u.losses}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// Ranks Component
function Ranks() {
  const { user } = useAuth();
  const [ranks, setRanks] = useState([]);

  useEffect(() => {
    api.get('/ranks').then(res => setRanks(res.data));
  }, []);

  const editRank = async (rank) => {
    const xp = prompt('Enter new XP requirement:', rank.xpRequired);
    const gifts = prompt('Enter gifts (comma separated):', rank.gifts.join(', '));

    if (xp && gifts) {
      try {
        await api.put(`/ranks/${rank.id}`, {
          xpRequired: parseInt(xp),
          gifts: gifts.split(',').map(g => g.trim())
        });
        toast.success('Rank updated!');
        api.get('/ranks').then(res => setRanks(res.data));
      } catch (err) {
        toast.error('Failed to update rank');
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6">
        <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#333333]">
          <h2 className="font-['Black_Ops_One'] text-4xl mb-8">
            RANK <span className="text-[#eab308]">SYSTEM</span>
          </h2>
          <div className="grid md:grid-cols-2 gap-4">
            {ranks.map((rank, i) => (
              <div
                key={rank.id}
                className={`bg-black p-5 rounded-lg border-l-4 ${
                  i < 5 ? 'border-gray-700' : i < 10 ? 'border-blue-700' : i < 15 ? 'border-purple-700' : 'border-[#eab308]'
                } hover:bg-gray-900 transition group`}
              >
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`text-2xl font-['Black_Ops_One'] ${
                        i < 5 ? 'text-gray-400' : i < 10 ? 'text-blue-400' : i < 15 ? 'text-purple-400' : 'text-[#eab308]'
                      }`}>
                        {rank.name}
                      </span>
                      {user?.role === 'admin' && (
                        <button
                          onClick={() => editRank(rank)}
                          className="text-xs text-gray-600 hover:text-white opacity-0 group-hover:opacity-100 transition"
                        >
                          <i className="fa-solid fa-pen-to-square"></i>
                        </button>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 uppercase mt-1">Rank #{rank.id}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-[#eab308] font-bold text-lg">{rank.xpRequired.toLocaleString()} XP</p>
                    <p className="text-xs text-gray-500">HP Range: {rank.hpMin}-{rank.hpMax}</p>
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t border-gray-800">
                  <p className="text-xs text-gray-400 uppercase font-bold mb-2">Gifts Unlocked:</p>
                  <div className="flex flex-wrap gap-2">
                    {rank.gifts.map((gift, idx) => (
                      <span key={idx} className="text-xs bg-gray-800 text-white px-2 py-1 rounded border border-gray-700">
                        <i className="fa-solid fa-gift text-[#dc2626] mr-1"></i>{gift}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Admin Component
function Admin() {
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [fights, setFights] = useState([]);

  useEffect(() => {
    if (user?.role === 'admin') {
      loadData();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  const loadData = async () => {
    try {
      const [usersRes, fightsRes] = await Promise.all([
        api.get('/users'),
        api.get('/fights')
      ]);
      setUsers(usersRes.data);
      setFights(fightsRes.data);
    } catch (err) {
      toast.error('Failed to load data');
    }
  };

  const approveFight = async (fightId) => {
    try {
      await api.put(`/fights/${fightId}`, { status: 'completed' });
      toast.success('Fight approved!');
      loadData();
    } catch (err) {
      toast.error('Failed to approve fight');
    }
  };

  const selectWinner = async (fightId, winnerId) => {
    try {
      await api.put(`/fights/${fightId}/selectwinner`, { winnerId });
      toast.success('Winner selected!');
      loadData();
    } catch (err) {
      toast.error('Failed to select winner');
    }
  };

  const deleteUser = async (userId, name) => {
    if (window.confirm(`Delete ${name}? This cannot be undone!`)) {
      try {
        await api.delete(`/admin/user/${userId}`);
        toast.success('User deleted');
        loadData();
      } catch (err) {
        toast.error('Failed to delete user');
      }
    }
  };

  const editUser = async (u) => {
    const hp = prompt('HP (0-100):', u.hp);
    const xp = prompt('XP:', u.xp);

    if (hp && xp) {
      try {
        await api.put(`/admin/user/${u.id}`, {
          hp: parseInt(hp),
          xp: parseInt(xp)
        });
        toast.success('User updated');
        loadData();
      } catch (err) {
        toast.error('Failed to update user');
      }
    }
  };

  const pending = fights.filter(f => f.status === 'review' || f.status === 'disputed');

  if (user?.role !== 'admin') return <Navigate to="/dashboard" />;

  return (
    <div className="min-h-screen bg-[#050505] text-white">
      <Navbar />
      <div className="container mx-auto p-6">
        <div className="bg-[#1e1e1e] p-6 rounded-lg border border-[#eab308]">
          <h2 className="font-['Black_Ops_One'] text-4xl text-[#eab308] mb-8">ADMIN PANEL</h2>

          {/* Pending Reviews */}
          <div className="mb-8">
            <h3 className="text-xl mb-4">
              <i className="fa-solid fa-scale-balanced text-[#dc2626]"></i> PENDING REVIEWS
            </h3>
            <div className="space-y-4">
              {pending.map(f => {
                const isDisputed = f.status === 'disputed';
                return (
                  <div key={f.id} className={`bg-black p-4 rounded border ${isDisputed ? 'border-orange-600/50' : 'border-yellow-600/50'}`}>
                    <div className="flex justify-between items-start mb-3">
                      <div>
                        <p className="text-white font-bold text-lg">
                          {f.p1?.name} <span className="text-gray-500 mx-2">VS</span> {f.p2?.name}
                        </p>
                        {isDisputed ? (
                          <p className="text-xs text-orange-500 uppercase mt-1">
                            <i className="fa-solid fa-triangle-exclamation"></i> BOTH CLAIMED VICTORY
                          </p>
                        ) : (
                          <p className="text-xs text-yellow-500 uppercase mt-1">
                            Claimed Winner: {f.winnerClaimId?.name}
                          </p>
                        )}
                      </div>
                    </div>
                    {isDisputed ? (
                      <div className="flex gap-2">
                        <button
                          onClick={() => selectWinner(f.id, f.p1?.id)}
                          className="flex-1 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded font-bold text-sm transition"
                        >
                          {f.p1?.name} WINS
                        </button>
                        <button
                          onClick={() => selectWinner(f.id, f.p2?.id)}
                          className="flex-1 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded font-bold text-sm transition"
                        >
                          {f.p2?.name} WINS
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => approveFight(f.id)}
                        className="bg-green-600 hover:bg-green-500 text-white px-5 py-2 rounded font-bold text-sm transition w-full"
                      >
                        APPROVE CLAIM
                      </button>
                    )}
                  </div>
                );
              })}
              {!pending.length && <p className="text-gray-500 italic text-center py-6">No pending reviews</p>}
            </div>
          </div>

          {/* User Management */}
          <div>
            <h3 className="text-xl mb-4">
              <i className="fa-solid fa-users-gear text-blue-500"></i> FIGHTER DATABASE
            </h3>
            <div className="grid md:grid-cols-2 gap-4">
              {users.map(u => (
                <div key={u.id} className="bg-black p-4 rounded border border-gray-800 flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <img
                      src={u.avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(u.name)}&background=222&color=888`}
                      className="w-10 h-10 rounded-full"
                      alt={u.name}
                    />
                    <div>
                      <p className="text-white font-bold text-sm">
                        {u.name} {u.role === 'admin' && <span className="text-[10px] bg-yellow-600 px-1 rounded ml-1 text-black">ADMIN</span>}
                      </p>
                      <p className="text-xs text-gray-400">HP: {u.hp} | XP: {u.xp} | {u.rank}</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => editUser(u)}
                      className="bg-gray-800 hover:bg-blue-600 text-white px-3 py-1 rounded text-xs border border-gray-700 transition uppercase font-bold"
                    >
                      Edit
                    </button>
                    {u.id !== user.id && (
                      <button
                        onClick={() => deleteUser(u.id, u.name)}
                        className="bg-gray-800 hover:bg-red-600 text-white px-3 py-1 rounded text-xs border border-gray-700 transition uppercase font-bold"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Main App Component
function App() {
  return (
    <AuthProvider>
      <Router>
        <ToastContainer
          position="top-right"
          autoClose={3000}
          hideProgressBar={false}
          theme="dark"
        />
        <AppRoutes />
      </Router>
    </AuthProvider>
  );
}

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="text-white text-2xl">Loading...</div>
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/" element={!user ? <LandingPage /> : <Navigate to="/dashboard" />} />
      <Route path="/login" element={!user ? <Login /> : <Navigate to="/dashboard" />} />
      <Route path="/register" element={!user ? <Register /> : <Navigate to="/dashboard" />} />
      <Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/login" />} />
      <Route path="/fighters" element={user ? <Fighters /> : <Navigate to="/login" />} />
      {/* Highlights Route Removed */}
      <Route path="/profile" element={user ? <Profile /> : <Navigate to="/login" />} />
      <Route path="/rankings" element={user ? <Rankings /> : <Navigate to="/login" />} />
      <Route path="/ranks" element={user ? <Ranks /> : <Navigate to="/login" />} />
      <Route path="/admin" element={user ? <Admin /> : <Navigate to="/login" />} />
    </Routes>
  );
}

export default App;
