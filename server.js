const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const xlsx = require('xlsx');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de la base de datos
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'lab_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'tu-secreto-seguro',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Configurar multer para upload de archivos
const upload = multer({ dest: 'uploads/' });

// ========================= MIDDLEWARES DE AUTENTICACIÓN =========================

// Middleware para verificar que el usuario está logeado
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Debes estar logeado' });
    }
    next();
}

// Middleware para verificar rol de admin
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.tipo_usuario !== 'admin') {
        return res.status(403).json({ error: 'Acceso denegado. Solo administrador' });
    }
    next();
}

// Middleware para verificar rol de proveedor
function requireProveedor(req, res, next) {
    if (!req.session.user || req.session.user.tipo_usuario !== 'proveedor') {
        return res.status(403).json({ error: 'Acceso denegado. Solo proveedor' });
    }
    next();
}

// Middleware para verificar rol de cliente
function requireCliente(req, res, next) {
    if (!req.session.user || req.session.user.tipo_usuario !== 'cliente') {
        return res.status(403).json({ error: 'Acceso denegado. Solo cliente' });
    }
    next();
}

// ========================= INICIALIZAR BASE DE DATOS =========================

async function initializeDatabase() {
    try {
        // Crear tabla de códigos de acceso
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS codigos_acceso (
                codigo VARCHAR(10) PRIMARY KEY,
                tipo_usuario VARCHAR(20) NOT NULL
            )
        `);

        // Crear tabla de usuarios
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                tipo_usuario VARCHAR(20) DEFAULT 'cliente',
                nombre VARCHAR(100),
                correo VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Crear tabla de instrumentos
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS instrumentos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                categoria VARCHAR(50),
                estado ENUM('DISPONIBLE', 'PRESTADO', 'MANTENIMIENTO') DEFAULT 'DISPONIBLE',
                ubicacion VARCHAR(100),
                proveedor_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (proveedor_id) REFERENCES usuarios(id) ON DELETE SET NULL
            )
        `);

        // Crear tabla de pedidos
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS pedidos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cliente_id INT NOT NULL,
                instrumento_id INT NOT NULL,
                proveedor_id INT NOT NULL,
                cantidad INT DEFAULT 1,
                estado ENUM('PENDIENTE', 'CONFIRMADO', 'ENVIADO', 'ENTREGADO', 'CANCELADO') DEFAULT 'PENDIENTE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (cliente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                FOREIGN KEY (instrumento_id) REFERENCES instrumentos(id) ON DELETE CASCADE,
                FOREIGN KEY (proveedor_id) REFERENCES usuarios(id) ON DELETE CASCADE
            )
        `);

        // Insertar códigos de acceso por defecto
        const defaultCodes = [
            ['ADMIN123', 'admin'],
            ['CLIENTE456', 'cliente'],
            ['PROVEEDOR789', 'proveedor']
        ];

        for (const [codigo, tipo] of defaultCodes) {
            await pool.execute(
                'INSERT IGNORE INTO codigos_acceso (codigo, tipo_usuario) VALUES (?, ?)',
                [codigo, tipo]
            );
        }

        // Insertar usuario admin por defecto
        const hashedPassword = await bcrypt.hash('password', 10);
        await pool.execute(
            'INSERT IGNORE INTO usuarios (username, password_hash, tipo_usuario, nombre, correo) VALUES (?, ?, ?, ?, ?)',
            ['admin', hashedPassword, 'admin', 'Administrador', 'admin@lab.com']
        );

        // Insertar usuario proveedor de prueba
        const hashedPasswordProv = await bcrypt.hash('password', 10);
        await pool.execute(
            'INSERT IGNORE INTO usuarios (username, password_hash, tipo_usuario, nombre, correo) VALUES (?, ?, ?, ?, ?)',
            ['proveedor1', hashedPasswordProv, 'proveedor', 'Proveedor Uno', 'proveedor1@lab.com']
        );

        // Insertar usuario cliente de prueba
        const hashedPasswordCli = await bcrypt.hash('password', 10);
        await pool.execute(
            'INSERT IGNORE INTO usuarios (username, password_hash, tipo_usuario, nombre, correo) VALUES (?, ?, ?, ?, ?)',
            ['cliente1', hashedPasswordCli, 'cliente', 'Cliente Uno', 'cliente1@lab.com']
        );

        // Insertar instrumentos de prueba
        await pool.execute(`
            INSERT IGNORE INTO instrumentos (nombre, categoria, estado, ubicacion, proveedor_id) VALUES 
            ('Microscopio Óptico', 'Microscopía', 'DISPONIBLE', 'Laboratorio A', 2),
            ('Centrífuga', 'Separación', 'DISPONIBLE', 'Laboratorio B', 2),
            ('Espectrómetro', 'Análisis', 'DISPONIBLE', 'Laboratorio C', 2),
            ('Pipeta Automática', 'Medición', 'DISPONIBLE', 'Laboratorio A', 2)
        `);

        // Insertar pedidos de prueba
        await pool.execute(`
            INSERT IGNORE INTO pedidos (cliente_id, instrumento_id, proveedor_id, cantidad, estado) VALUES 
            (3, 1, 2, 1, 'PENDIENTE'),
            (3, 2, 2, 2, 'CONFIRMADO'),
            (3, 3, 2, 1, 'ENVIADO')
        `);

        console.log('✅ Base de datos inicializada correctamente con datos de prueba');
        console.log('👤 Usuarios de prueba creados:');
        console.log('   - admin / password (Administrador)');
        console.log('   - proveedor1 / password (Proveedor)');
        console.log('   - cliente1 / password (Cliente)');
        
    } catch (error) {
        console.log('ℹ️ Configuración de base de datos:', error.message);
    }
}

// ========================= RUTAS ESTÁTICAS =========================

// Ruta raíz - redirigir a login o index
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/index.html');
    } else {
        res.redirect('/login.html');
    }
});

// Servir páginas HTML protegidas
app.get('/index.html', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

app.get('/prestamos', (req, res) => {
    res.sendFile(__dirname + '/public/prestamos.html');
});

app.get('/prestamos.html', (req, res) => {
    res.sendFile(__dirname + '/public/prestamos.html');
});

app.get('/instrumentos', (req, res) => {
    res.sendFile(__dirname + '/public/instrumentos.html');
});

app.get('/instrumentos.html', (req, res) => {
    res.sendFile(__dirname + '/public/instrumentos.html');
});

app.get('/busqueda', (req, res) => {
    res.sendFile(__dirname + '/public/busqueda.html');
});

app.get('/busqueda.html', (req, res) => {
    res.sendFile(__dirname + '/public/busqueda.html');
});

// ========================= RUTAS DE AUTENTICACIÓN =========================

// Login - soporta tanto JSON como form-urlencoded
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            // Si es un formulario tradicional, redirigir al login con error
            if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
                return res.redirect('/login.html?error=Usuario+y+contraseña+requeridos');
            }
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }

        const [users] = await pool.execute(
            'SELECT * FROM usuarios WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
                return res.redirect('/login.html?error=Usuario+no+encontrado');
            }
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
                return res.redirect('/login.html?error=Contraseña+incorrecta');
            }
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        req.session.user = {
            id: user.id,
            username: user.username,
            tipo_usuario: user.tipo_usuario,
            nombre: user.nombre,
            correo: user.correo
        };

        // Si es un formulario tradicional, redirigir a index
        if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
            return res.redirect('/index.html');
        }

        res.json({ 
            success: true,
            message: 'Login exitoso',
            user: req.session.user
        });

    } catch (error) {
        if (req.headers['content-type'] && req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
            return res.redirect('/login.html?error=Error+en+servidor');
        }
        res.status(500).json({ error: error.message });
    }
});

// Registro
app.post('/registro', async (req, res) => {
    try {
        const { username, password, codigo, nombre, correo } = req.body;

        if (!username || !password || !codigo) {
            return res.status(400).json({ error: 'Datos incompletos' });
        }

        // Verificar código de acceso
        const [codes] = await pool.execute(
            'SELECT * FROM codigos_acceso WHERE codigo = ?',
            [codigo]
        );

        if (codes.length === 0) {
            return res.status(400).json({ error: 'Código de acceso inválido' });
        }

        const tipoUsuario = codes[0].tipo_usuario;

        // Verificar si el usuario ya existe
        const [existingUsers] = await pool.execute(
            'SELECT * FROM usuarios WHERE username = ?',
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }

        // Crear usuario
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO usuarios (username, password_hash, tipo_usuario, nombre, correo) VALUES (?, ?, ?, ?, ?)',
            [username, hashedPassword, tipoUsuario, nombre || username, correo || '']
        );

        res.json({ 
            success: true,
            message: 'Registro exitoso'
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/login.html?error=Error+al+cerrar+sesión');
        }
        // Redirigir al login después de cerrar sesión
        res.redirect('/login.html');
    });
});

// Obtener tipo de usuario actual
app.get('/tipo-usuario', requireLogin, (req, res) => {
    res.json({
        id: req.session.user.id,
        username: req.session.user.username,
        tipo_usuario: req.session.user.tipo_usuario,
        nombre: req.session.user.nombre
    });
});

// ========================= RUTAS DE INSTRUMENTOS =========================

// Listar todos los instrumentos
app.get('/api/instrumentos', requireLogin, async (req, res) => {
    try {
        const [instrumentos] = await pool.execute(`
            SELECT i.*, u.nombre as proveedor_nombre 
            FROM instrumentos i
            LEFT JOIN usuarios u ON i.proveedor_id = u.id
            ORDER BY i.id
        `);
        res.json(instrumentos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API para obtener usuarios (JSON)
app.get('/api/usuarios', requireLogin, requireAdmin, async (req, res) => {
    try {
        const [usuarios] = await pool.execute(`
            SELECT id, username, tipo_usuario, nombre, correo, created_at 
            FROM usuarios 
            ORDER BY created_at DESC
        `);
        res.json(usuarios);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Buscar instrumentos
app.get('/api/instrumentos/buscar', requireLogin, async (req, res) => {
    try {
        const { q } = req.query;
        const [instrumentos] = await pool.execute(`
            SELECT i.*, u.nombre as proveedor_nombre 
            FROM instrumentos i
            LEFT JOIN usuarios u ON i.proveedor_id = u.id
            WHERE i.nombre LIKE ? OR i.categoria LIKE ? OR i.ubicacion LIKE ?
            ORDER BY i.id
        `, [`%${q}%`, `%${q}%`, `%${q}%`]);
        res.json(instrumentos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Crear instrumento (admin y proveedor)
app.post('/api/instrumentos', requireLogin, async (req, res) => {
    try {
        const { nombre, categoria, estado, ubicacion } = req.body;
        
        if (!nombre) {
            return res.status(400).json({ error: 'Nombre requerido' });
        }

        const proveedorId = req.session.user.tipo_usuario === 'proveedor' 
            ? req.session.user.id 
            : req.body.proveedor_id || null;

        const [result] = await pool.execute(
            'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion, proveedor_id) VALUES (?, ?, ?, ?, ?)',
            [nombre, categoria || '', estado || 'DISPONIBLE', ubicacion || '', proveedorId]
        );

        res.json({ 
            success: true, 
            id: result.insertId,
            message: 'Instrumento creado exitosamente'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Actualizar instrumento
app.put('/api/instrumentos/:id', requireLogin, async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, categoria, estado, ubicacion } = req.body;

        // Verificar propiedad
        const [instrumentos] = await pool.execute(
            'SELECT * FROM instrumentos WHERE id = ?',
            [id]
        );

        if (instrumentos.length === 0) {
            return res.status(404).json({ error: 'Instrumento no encontrado' });
        }

        const instrumento = instrumentos[0];
        if (req.session.user.tipo_usuario === 'proveedor' && instrumento.proveedor_id !== req.session.user.id) {
            return res.status(403).json({ error: 'No tienes permiso para editar este instrumento' });
        }

        await pool.execute(
            'UPDATE instrumentos SET nombre = ?, categoria = ?, estado = ?, ubicacion = ? WHERE id = ?',
            [nombre || instrumento.nombre, categoria || instrumento.categoria, estado || instrumento.estado, ubicacion || instrumento.ubicacion, id]
        );

        res.json({ success: true, message: 'Instrumento actualizado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Eliminar instrumento
app.delete('/api/instrumentos/:id', requireLogin, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar propiedad
        const [instrumentos] = await pool.execute(
            'SELECT * FROM instrumentos WHERE id = ?',
            [id]
        );

        if (instrumentos.length === 0) {
            return res.status(404).json({ error: 'Instrumento no encontrado' });
        }

        const instrumento = instrumentos[0];
        if (req.session.user.tipo_usuario === 'proveedor' && instrumento.proveedor_id !== req.session.user.id) {
            return res.status(403).json({ error: 'No tienes permiso para eliminar este instrumento' });
        }

        await pool.execute('DELETE FROM instrumentos WHERE id = ?', [id]);
        res.json({ success: true, message: 'Instrumento eliminado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================= RUTAS DE PEDIDOS - CLIENTE =========================

// Crear pedido (cliente)
app.post('/cliente/pedidos', requireLogin, requireCliente, async (req, res) => {
    try {
        const { instrumento_id, cantidad } = req.body;
        const cliente_id = req.session.user.id;

        if (!instrumento_id || !cantidad) {
            return res.status(400).json({ error: 'Datos incompletos' });
        }

        // Obtener instrumento y su proveedor
        const [instrumentos] = await pool.execute(
            'SELECT * FROM instrumentos WHERE id = ?',
            [instrumento_id]
        );

        if (instrumentos.length === 0) {
            return res.status(404).json({ error: 'Instrumento no encontrado' });
        }

        const instrumento = instrumentos[0];
        const proveedor_id = instrumento.proveedor_id;

        // Crear pedido
        const [result] = await pool.execute(
            'INSERT INTO pedidos (cliente_id, instrumento_id, proveedor_id, cantidad, estado) VALUES (?, ?, ?, ?, ?)',
            [cliente_id, instrumento_id, proveedor_id, cantidad, 'PENDIENTE']
        );

        res.json({ 
            success: true,
            id: result.insertId,
            message: 'Pedido creado exitosamente'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ver catálogo de instrumentos disponibles (cliente)
app.get('/cliente/catalogo', requireLogin, requireCliente, async (req, res) => {
    try {
        const [instrumentos] = await pool.execute(`
            SELECT i.*, u.nombre as proveedor_nombre 
            FROM instrumentos i
            LEFT JOIN usuarios u ON i.proveedor_id = u.id
            WHERE i.estado = 'DISPONIBLE'
            ORDER BY i.id
        `);
        res.json(instrumentos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ver mis pedidos (cliente)
app.get('/cliente/mis-pedidos', requireLogin, requireCliente, async (req, res) => {
    try {
        const [pedidos] = await pool.execute(`
            SELECT p.*, 
                   i.nombre as instrumento_nombre,
                   u.nombre as proveedor_nombre
            FROM pedidos p
            JOIN instrumentos i ON p.instrumento_id = i.id
            JOIN usuarios u ON p.proveedor_id = u.id
            WHERE p.cliente_id = ?
            ORDER BY p.created_at DESC
        `, [req.session.user.id]);

        res.json(pedidos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cancelar pedido (cliente)
app.put('/cliente/pedidos/:id/cancelar', requireLogin, requireCliente, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar propiedad y estado
        const [pedidos] = await pool.execute(
            'SELECT * FROM pedidos WHERE id = ? AND cliente_id = ?',
            [id, req.session.user.id]
        );

        if (pedidos.length === 0) {
            return res.status(404).json({ error: 'Pedido no encontrado' });
        }

        const pedido = pedidos[0];
        if (pedido.estado !== 'PENDIENTE') {
            return res.status(400).json({ error: 'Solo se pueden cancelar pedidos pendientes' });
        }

        await pool.execute(
            'UPDATE pedidos SET estado = ? WHERE id = ?',
            ['CANCELADO', id]
        );

        res.json({ success: true, message: 'Pedido cancelado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================= RUTAS DE PEDIDOS - PROVEEDOR =========================

// Ver mis pedidos (proveedor) - ¡ESTA ERA LA RUTA QUE FALTABA!
app.get('/proveedor/mis-pedidos', requireLogin, requireProveedor, async (req, res) => {
    try {
        const [pedidos] = await pool.execute(`
            SELECT p.*, 
                   i.nombre as instrumento_nombre,
                   u.nombre as cliente_nombre
            FROM pedidos p
            JOIN instrumentos i ON p.instrumento_id = i.id
            JOIN usuarios u ON p.cliente_id = u.id
            WHERE p.proveedor_id = ?
            ORDER BY p.created_at DESC
        `, [req.session.user.id]);

        res.json(pedidos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Confirmar pedido (proveedor)
app.put('/proveedor/pedidos/:id/confirmar', requireLogin, requireProveedor, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar propiedad y estado
        const [pedidos] = await pool.execute(
            'SELECT * FROM pedidos WHERE id = ? AND proveedor_id = ?',
            [id, req.session.user.id]
        );

        if (pedidos.length === 0) {
            return res.status(404).json({ error: 'Pedido no encontrado' });
        }

        const pedido = pedidos[0];
        if (pedido.estado !== 'PENDIENTE') {
            return res.status(400).json({ error: 'Solo se pueden confirmar pedidos pendientes' });
        }

        await pool.execute(
            'UPDATE pedidos SET estado = ? WHERE id = ?',
            ['CONFIRMADO', id]
        );

        res.json({ success: true, message: 'Pedido confirmado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Enviar pedido (proveedor)
app.put('/proveedor/pedidos/:id/enviar', requireLogin, requireProveedor, async (req, res) => {
    try {
        const { id } = req.params;

        // Verificar propiedad y estado
        const [pedidos] = await pool.execute(
            'SELECT * FROM pedidos WHERE id = ? AND proveedor_id = ?',
            [id, req.session.user.id]
        );

        if (pedidos.length === 0) {
            return res.status(404).json({ error: 'Pedido no encontrado' });
        }

        const pedido = pedidos[0];
        if (pedido.estado !== 'CONFIRMADO') {
            return res.status(400).json({ error: 'Solo se pueden enviar pedidos confirmados' });
        }

        await pool.execute(
            'UPDATE pedidos SET estado = ? WHERE id = ?',
            ['ENVIADO', id]
        );

        res.json({ success: true, message: 'Pedido marcado como enviado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================= RUTAS ADMIN =========================

// Ver usuarios - Página HTML
app.get('/ver-usuarios', requireLogin, requireAdmin, async (req, res) => {
    try {
        const [usuarios] = await pool.execute(`
            SELECT id, username, tipo_usuario, nombre, correo, created_at 
            FROM usuarios 
            ORDER BY created_at DESC
        `);
        
        // Servir página HTML con los usuarios
        res.send(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestionar Usuarios - Lab Instruments</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="styless.css" rel="stylesheet">
</head>
<body>
    <div id="navbar"></div>
    
    <div class="container mt-5">
        <div class="row">
            <div class="col-12">
                <div class="card card-custom">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h4 class="mb-0"><i class="fas fa-users me-2"></i>Gestionar Usuarios</h4>
                        <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#crearUsuarioModal">
                            <i class="fas fa-user-plus me-1"></i>Nuevo Usuario
                        </button>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="table-light">
                                    <tr>
                                        <th>ID</th>
                                        <th>Usuario</th>
                                        <th>Nombre</th>
                                        <th>Rol</th>
                                        <th>Correo</th>
                                        <th>Creado</th>
                                        <th>Acciones</th>
                                    </tr>
                                </thead>
                                <tbody id="usuariosTable">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal para crear usuario -->
    <div class="modal fade" id="crearUsuarioModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Crear Nuevo Usuario</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="crearUsuarioForm">
                        <div class="mb-3">
                            <label class="form-label">Usuario</label>
                            <input type="text" class="form-control" id="newUsername" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Contraseña</label>
                            <input type="password" class="form-control" id="newPassword" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Nombre</label>
                            <input type="text" class="form-control" id="newNombre">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Correo</label>
                            <input type="email" class="form-control" id="newCorreo">
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Rol</label>
                            <select class="form-select" id="newTipoUsuario" required>
                                <option value="">Selecciona un rol</option>
                                <option value="admin">Administrador</option>
                                <option value="cliente">Cliente</option>
                                <option value="proveedor">Proveedor</option>
                            </select>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="button" class="btn btn-primary" onclick="crearUsuario()">Crear</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            cargarNavbar();
            cargarUsuarios();
        });

        async function cargarNavbar() {
            try {
                const response = await fetch('navbar.html');
                const html = await response.text();
                document.getElementById('navbar').innerHTML = html;
                const scripts = document.getElementById('navbar').getElementsByTagName('script');
                for (let script of scripts) eval(script.innerHTML);
            } catch (error) {
                console.error('Error:', error);
            }
        }

        async function cargarUsuarios() {
            try {
                const response = await fetch('/api/usuarios');
                const usuarios = await response.json();
                const tbody = document.getElementById('usuariosTable');
                tbody.innerHTML = '';

                usuarios.forEach(usuario => {
                    const fecha = new Date(usuario.created_at).toLocaleDateString('es-ES');
                    const rolBadge = usuario.tipo_usuario === 'admin' ? 'danger' : 
                                   usuario.tipo_usuario === 'proveedor' ? 'success' : 'info';
                    const rolTexto = usuario.tipo_usuario === 'admin' ? 'Administrador' : 
                                    usuario.tipo_usuario === 'proveedor' ? 'Proveedor' : 'Cliente';
                    
                    const row = document.createElement('tr');
                    row.innerHTML = \`
                        <td>#\${usuario.id}</td>
                        <td>\${usuario.username}</td>
                        <td>\${usuario.nombre || '-'}</td>
                        <td><span class="badge bg-\${rolBadge}">\${rolTexto}</span></td>
                        <td>\${usuario.correo || '-'}</td>
                        <td>\${fecha}</td>
                        <td>
                            <button class="btn btn-sm btn-danger" onclick="eliminarUsuario(\${usuario.id})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    \`;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error:', error);
            }
        }

        async function crearUsuario() {
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const nombre = document.getElementById('newNombre').value;
            const correo = document.getElementById('newCorreo').value;
            const tipo_usuario = document.getElementById('newTipoUsuario').value;

            try {
                const response = await fetch('/admin/usuarios', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, nombre, correo, tipo_usuario })
                });

                if (response.ok) {
                    document.getElementById('crearUsuarioForm').reset();
                    const modal = bootstrap.Modal.getInstance(document.getElementById('crearUsuarioModal'));
                    modal.hide();
                    cargarUsuarios();
                    alert('Usuario creado exitosamente');
                } else {
                    alert('Error al crear usuario');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function eliminarUsuario(id) {
            if (!confirm('¿Está seguro de eliminar este usuario?')) return;

            try {
                const response = await fetch('/admin/usuarios/' + id, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    cargarUsuarios();
                    alert('Usuario eliminado');
                } else {
                    alert('Error al eliminar usuario');
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }
    </script>
</body>
</html>
        `);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Crear usuario (admin)
app.post('/admin/usuarios', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { username, password, tipo_usuario, nombre, correo } = req.body;

        if (!username || !password || !tipo_usuario) {
            return res.status(400).json({ error: 'Datos incompletos' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO usuarios (username, password_hash, tipo_usuario, nombre, correo) VALUES (?, ?, ?, ?, ?)',
            [username, hashedPassword, tipo_usuario, nombre || username, correo || '']
        );

        res.json({ 
            success: true,
            id: result.insertId,
            message: 'Usuario creado exitosamente'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Eliminar usuario (admin)
app.delete('/admin/usuarios/:id', requireLogin, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        if (parseInt(id) === req.session.user.id) {
            return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta' });
        }

        await pool.execute('DELETE FROM usuarios WHERE id = ?', [id]);
        res.json({ success: true, message: 'Usuario eliminado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================= RUTAS PARA EXCEL =========================

// Descargar Excel
app.get('/api/instrumentos/download', requireLogin, requireAdmin, async (req, res) => {
    try {
        const [instrumentos] = await pool.execute(`
            SELECT i.id, i.nombre, i.categoria, i.estado, i.ubicacion, 
                   u.nombre as proveedor
            FROM instrumentos i
            LEFT JOIN usuarios u ON i.proveedor_id = u.id
        `);

        const ws = xlsx.utils.json_to_sheet(instrumentos);
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, ws, 'Instrumentos');

        const filePath = path.join(__dirname, 'uploads', 'laboratorio_instrumentos.xlsx');
        xlsx.write(wb, { bookType: 'xlsx', type: 'file', cellFormula: true }, filePath);

        res.download(filePath, 'laboratorio_instrumentos.xlsx');
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Subir Excel
app.post('/api/instrumentos/upload', requireLogin, requireAdmin, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No se subió archivo' });
        }

        const workbook = xlsx.readFile(req.file.path);
        const sheet = workbook.Sheets[workbook.SheetNames[0]];
        const data = xlsx.utils.sheet_to_json(sheet);

        for (const row of data) {
            await pool.execute(
                'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?, ?, ?, ?)',
                [row.nombre, row.categoria, row.estado || 'DISPONIBLE', row.ubicacion]
            );
        }

        fs.unlinkSync(req.file.path);
        res.json({ 
            success: true,
            message: `${data.length} instrumentos importados correctamente`
        });
    } catch (error) {
        if (req.file) fs.unlinkSync(req.file.path);
        res.status(500).json({ error: error.message });
    }
});

// ========================= RUTA DE DEPURACIÓN =========================

app.get('/debug/pedidos', requireLogin, async (req, res) => {
    try {
        const [pedidos] = await pool.execute('SELECT * FROM pedidos');
        const [usuarios] = await pool.execute('SELECT id, username, tipo_usuario FROM usuarios');
        const [instrumentos] = await pool.execute('SELECT id, nombre FROM instrumentos');
        
        res.json({
            usuario_actual: req.session.user,
            pedidos: pedidos,
            usuarios: usuarios,
            instrumentos: instrumentos
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========================= INICIAR SERVIDOR =========================

async function startServer() {
    try {
        // Verificar conexión a la base de datos
        const connection = await pool.getConnection();
        console.log('✅ Conectado a MySQL correctamente');
        connection.release();

        // Inicializar base de datos
        await initializeDatabase();

        // Iniciar servidor
        app.listen(PORT, () => {
            console.log(`\n🚀 Servidor ejecutándose en http://localhost:${PORT}`);
            console.log(`📖 API Documentation: Ver README.md`);
        });
    } catch (error) {
        console.error('❌ Error al iniciar el servidor:', error);
        process.exit(1);
    }
}

startServer();

module.exports = app;
